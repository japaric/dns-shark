//! A DNS "spy" built on top of wireshark

// TODO remove all `dbg!` calls

use std::io::{BufRead, BufReader, Lines, Read};
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};

use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};

// TODO parse `Layers.dns` more, instead of using this
pub use serde_json::Value as DnsMessage;

type Result<T> = core::result::Result<T, Error>;
type Error = Box<dyn std::error::Error>;

pub struct DnsShark {
    child: Child,
    port: u16,
    stderr: Lines<BufReader<ChildStderr>>,
    stdout: ChildStdout,
}

impl DnsShark {
    /// Eavesdrop the given port using the loopback interface
    // TODO support other protocols like TCP
    pub fn eavesdrop(udp_port: u16) -> Result<Self> {
        let mut child = Command::new("tshark")
            // alternatively use `--log-level noisy` to see all the logs
            .args(["--log-level", "info", "--log-domain", "main"])
            .args(["-i", "lo", "-T", "json", "-O", "dns", "-f"])
            .arg(format!("udp port {udp_port}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or("could not retrieve handle to wireshark's stdout")?;

        let stderr = child
            .stderr
            .take()
            .ok_or("could not retrieve handle to wireshark's stderr")?;

        // wait until wireshark start capturing packets
        // FIXME this could block forever; add timeout
        let mut stderr = BufReader::new(stderr).lines();
        for res in stderr.by_ref() {
            let line = res?;
            dbg!(&line);
            if line.contains("Capture started") {
                break;
            }
        }

        Ok(Self {
            child,
            stdout,
            stderr,
            port: udp_port,
        })
    }

    pub fn into_messages(mut self) -> Result<DnsMessages> {
        // `Child::kill` does not terminate `tshark` cleanly so we send a signal
        // XXX should this use `libc::kill` for wider platform support?
        let status = Command::new("kill")
            .arg("-SIGINT")
            .arg(self.child.id().to_string())
            .status()?;

        dbg!(status);

        // wait until the message "NN packets captured" appears
        // wireshark will close stderr after printing that so exhausting
        // the file descriptor produces the same result
        for res in self.stderr.by_ref() {
            let line = res?;
            dbg!(line);
        }

        let mut output = vec![];
        self.stdout.read_to_end(&mut output)?;

        dbg!(output.len());

        let all_messages: Vec<Message> = serde_json::from_slice(&output)?;
        let mut incoming = vec![];
        let mut outgoing = vec![];

        for message in all_messages {
            let layers = message._source.layers;

            if layers.udp.dstport == self.port {
                incoming.push(layers.dns);
            } else if layers.udp.srcport == self.port {
                outgoing.push(layers.dns);
            } else {
                return Err(format!(
                    "unexpected UDP message found in wireshark trace: {:?}",
                    layers.udp
                )
                .into());
            }
        }

        Ok(DnsMessages { incoming, outgoing })
    }
}

// by default, `Child` will continue to run after it has been dropped, outliving its parent
// if necessary, terminate it here to avoid leaving `tshark` processes behind
impl Drop for DnsShark {
    fn drop(&mut self) {
        let res = self.child.kill();
        let _ = dbg!(res);
    }
}

#[derive(Debug)]
pub struct DnsMessages {
    pub incoming: Vec<DnsMessage>,
    pub outgoing: Vec<DnsMessage>,
}

#[derive(Deserialize)]
struct Message {
    _source: Source,
}

#[derive(Deserialize)]
struct Source {
    layers: Layers,
}

#[derive(Deserialize)]
struct Layers {
    // we use UDP layer information to determine the direction of the message
    udp: Udp,
    dns: serde_json::Value,
}

#[serde_as]
#[derive(Debug, Deserialize)]
struct Udp {
    #[serde(rename = "udp.dstport")]
    #[serde_as(as = "DisplayFromStr")]
    dstport: u16,

    #[serde(rename = "udp.srcport")]
    #[serde_as(as = "DisplayFromStr")]
    srcport: u16,
}

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, thread, time::Duration};

    use rand::Rng;

    use super::*;

    const MIN_PORT: u16 = 1024;

    #[test]
    fn it_works() -> Result<()> {
        let port = random_udp_port();
        let server = UdpSocket::bind(("127.0.0.1", port))?;

        let shark = DnsShark::eavesdrop(port)?;

        let mut delv = Command::new("delv")
            .args(["@127.0.0.1", "rustacean.net.", "-p"])
            .arg(port.to_string())
            .spawn()?;

        // wait until `delv` sends UDP data
        let mut buf = [0; 1024];
        let (read, _peer) = server.recv_from(&mut buf)?;
        assert_ne!(0, dbg!(read));

        delv.kill()?;

        // wireshark does not signal in its logs when it has finished parsing a new packet so
        // we wait to give it a chance to parse the UDP data `delv` sent
        thread::sleep(Duration::from_millis(500));

        let DnsMessages { incoming, outgoing } = shark.into_messages()?;

        assert!(outgoing.is_empty());
        assert_eq!(1, incoming.len());

        let [message] = incoming.try_into().unwrap();

        let additional_records = message["Additional records"].as_object().unwrap();

        let mut found_opt_record = false;
        for (record_ty, record) in additional_records {
            if record_ty.ends_with("type OPT") {
                assert!(!found_opt_record);
                found_opt_record = true;

                let do_bit = record["dns.resp.z_tree"]["dns.resp.z.do"]
                    .as_str()
                    .unwrap()
                    .parse::<u8>()
                    .unwrap();
                assert_eq!(1, do_bit);

                let udp_payload_size = record["dns.rr.udp_payload_size"]
                    .as_str()
                    .unwrap()
                    .parse::<u16>()
                    .unwrap();
                assert!(udp_payload_size > 1220);
            }
        }

        assert!(found_opt_record);

        Ok(())
    }

    #[test]
    fn drop_cleans_up_process() -> Result<()> {
        let shark = DnsShark::eavesdrop(random_udp_port())?;
        let pid = shark.child.id();
        dbg!(pid);
        drop(shark);

        let output = Command::new("ps")
            .args(["-f", "-p"])
            .arg(pid.to_string())
            .output()?;

        let stdout = core::str::from_utf8(&output.stdout)?;

        let process_is_defunct = dbg!(stdout).contains("<defunct>");
        assert!(process_is_defunct);

        Ok(())
    }

    fn random_udp_port() -> u16 {
        rand::thread_rng().gen_range(MIN_PORT..u16::MAX)
    }
}
