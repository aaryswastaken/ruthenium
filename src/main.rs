use tokio::net::{TcpListener, TcpStream};
// use tokio::stream::StreamExt;
use futures::SinkExt;
use futures::StreamExt;
use std::convert::TryFrom;
use std::net;
use std::str::FromStr;
use tokio_util::codec::{FramedRead, FramedWrite};

use ldap3_proto::simple::*;
use ldap3_proto::LdapCodec;
use ldap3_proto::simple::LdapFilter::*;

mod dbm;

pub struct LdapSession {
    dn: String,
    wl: dbm::Whitelist
}

fn fmt(filter: &LdapFilter) -> String{
    let s: String = match filter {
        And(filters) => filters.iter().map(|e| fmt(e)).collect::<Vec<String>>().join(" AND "),
        Or(filters)  => filters.iter().map(|e| fmt(e)).collect::<Vec<String>>().join(" OR "),
        Not(not) => format!("NOT {}", fmt(not)),

        Equality(str1, str2) => format!("{} == {}", str1, str2),
        Substring(_str1, _idk) => "idk".to_string(),

        Present(str1) => format!("Present: {}", str1) 
    };

    return format!("({})", s);
}

impl LdapSession {
    pub fn do_bind(&mut self, sbr: &SimpleBindRequest) -> LdapMsg {
        if sbr.dn == "cn=Directory Manager" && sbr.pw == "password" {
            self.dn = sbr.dn.to_string();
            sbr.gen_success()
        } else if sbr.dn == "" && sbr.pw == "" {
            self.dn = "Anonymous".to_string();
            sbr.gen_success()
        } else if sbr.dn == "cn=user01,ou=users,dc=example,dc=org" && sbr.pw == "user01" {
            self.dn = sbr.dn.to_string();
            sbr.gen_success()
        } else if sbr.dn == "cn=user01,ou=users,dc=example,dc=org" && sbr.pw == "user01" {
            self.dn = sbr.dn.to_string();
            sbr.gen_success()
        } else if sbr.dn == "TEST" && sbr.pw == "TEST" {
            self.dn = sbr.dn.to_string();
            sbr.gen_success()
        } else {
            sbr.gen_invalid_cred()
        }
    }

    pub fn do_search(&mut self, lsr: &SearchRequest) -> Vec<LdapMsg> {
        println!("new request, {}, {}", lsr.base, fmt(&lsr.filter));
        
        let out:Vec<LdapMsg> = match lsr.base.as_str() {
            "" => vec![
                lsr.gen_result_entry(LdapSearchResultEntry {
                    dn: "".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec!["RutheniumLDAPRootDSE".to_string(),"top".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "namingContexts".to_string(),
                            vals: vec!["dc=example,dc=org".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "entryDN".to_string(),
                            vals: vec!["".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "subschemaSubentry".to_string(),
                            vals: vec!["cn=Subschema".to_string()]
                        },
                    ]
                }),

                lsr.gen_result_entry(LdapSearchResultEntry {
                    dn: "dc=example,dc=org".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec!["dcObject".to_string(),"organization".to_string()]
                        },
                        LdapPartialAttribute {                     
                            atype: "dc".to_string(),
                            vals: vec!["example".to_string()],
                        },
                        LdapPartialAttribute {                     
                            atype: "o".to_string(),
                            vals: vec!["example".to_string()],
                        },
                    ]
                }), lsr.gen_success()],
            "dc=org" => vec![
                lsr.gen_result_entry(LdapSearchResultEntry {
                    dn: "dc=example,dc=org".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec!["dcObject".to_string(),"organization".to_string()]
                        },
                        LdapPartialAttribute {                     
                            atype: "dc".to_string(),
                            vals: vec!["example".to_string()],
                        },
                        LdapPartialAttribute {                     
                            atype: "o".to_string(),
                            vals: vec!["example".to_string()],
                        },
                    ]
                }), lsr.gen_success()],
            "dc=example,dc=org" => vec![
                lsr.gen_result_entry(LdapSearchResultEntry {
                    dn: "ou=users,dc=example,dc=org".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec!["organizationalUnit".to_string()]
                        },
                        LdapPartialAttribute {
                            atype: "ou".to_string(),
                            vals: vec!["users".to_string()]
                        }
                    ]
                }), lsr.gen_success()],
            "ou=users,dc=example,dc=org" => self.wl.generate_ldap_entries(lsr), 
            &_ => vec![lsr.gen_error(LdapResultCode::Unavailable, "Unsupported operation".to_string())]  
        };

        println!("Length of the response: {}", out.len());

        return out;
    }

    pub fn do_whoami(&mut self, wr: &WhoamiRequest) -> LdapMsg {
        wr.gen_success(format!("dn: {}", self.dn).as_str())
    }
}

async fn handle_client(socket: TcpStream, _paddr: net::SocketAddr) {
    // Configure the codec etc.
    let (r, w) = tokio::io::split(socket);
    let mut reqs = FramedRead::new(r, LdapCodec);
    let mut resp = FramedWrite::new(w, LdapCodec);

    let whitelist = dbm::read_from_file("./whitelist".to_string(), "ou=users,dc=example,dc=org".to_string());

    let mut session = LdapSession {
        dn: "Anonymous".to_string(),
        wl: whitelist
    };

    while let Some(msg) = reqs.next().await {
        let server_op = match msg
            .map_err(|_e| ())
            .and_then(|msg| ServerOps::try_from(msg))
        {
            Ok(v) => v,
            Err(_) => {
                let _err = resp
                    .send(DisconnectionNotice::gen(
                        LdapResultCode::Other,
                        "Internal Server Error",
                    ))
                    .await;
                let _err = resp.flush().await;
                return;
            }
        };

        let result = match server_op {
            ServerOps::SimpleBind(sbr) => vec![session.do_bind(&sbr)],
            ServerOps::Search(sr) => session.do_search(&sr),
            ServerOps::Unbind(_) => {
                // No need to notify on unbind (per rfc4511)
                return;
            }
            ServerOps::Whoami(wr) => vec![session.do_whoami(&wr)],
        };

        for rmsg in result.into_iter() {
            if let Err(_) = resp.send(rmsg).await {
                return;
            }
        }

        if let Err(_) = resp.flush().await {
            return;
        }
    }
    // Client disconnected
}

async fn acceptor(listener: Box<TcpListener>) {
    loop {
        match listener.accept().await {
            Ok((socket, paddr)) => {
                tokio::spawn(handle_client(socket, paddr));
            }
            Err(_e) => {
                //pass
            }
        }
    }
}

#[tokio::main]
async fn main() -> () {
    let addr = net::SocketAddr::from_str("0.0.0.0:12345").unwrap();
    let listener = Box::new(TcpListener::bind(&addr).await.unwrap());

    // Initiate the acceptor task.
    tokio::spawn(acceptor(listener));

    println!("started ldap://0.0.0.0:12345 ...");
    tokio::signal::ctrl_c().await.unwrap();
}