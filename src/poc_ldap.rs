use tokio::net::{TcpListener, TcpStream};
// use tokio::stream::StreamExt;
use futures::SinkExt;
use futures::StreamExt;
use std::convert::TryFrom;
use std::net;
use std::str::FromStr;
use std::vec;
use tokio_util::codec::{FramedRead, FramedWrite};

use ldap3_proto::simple::*;
use ldap3_proto::proto::LdapFilter::{self, *};
use ldap3_proto::LdapCodec;

pub struct LdapSession {
    dn: String,
    ou: String,
    base_attrs: Vec<LdapPartialAttribute>,
    dn_attrs: Vec<LdapPartialAttribute>,
    ou_attrs: Vec<LdapPartialAttribute>
}

trait Format {
    fn format(&self) -> String;
}

impl Format for LdapFilter {
    fn format(&self) -> String{
        let s: String = match self {
            And(filters) => filters.iter().map(|e| format!("A{}", e.format())).collect::<Vec<String>>().join(" AND "),
            Or(filters)  => filters.iter().map(|e| format!("O{}", e.format())).collect::<Vec<String>>().join(" OR "),
            Not(not) => format!("NOT {}", not.format()),
    
            Equality(str1, str2) => format!("{} == {}", str1, str2),
            Substring(_str1, _idk) => "idk".to_string(),
    
            Present(str1) => format!("Present: {}", str1) 
        };
    
        return format!("({})", s);
    }
}

impl Format for SearchRequest {
    fn format(&self) -> String {
        let mut out: String = String::new();

        out.push_str("----------------------\n");
        out.push_str(format!("_id: {}\nbase: {}\n", self.msgid, &self.base).as_str());
        out.push_str(format!("scope: {}\nattrs: {}\n",
            match self.scope {
                LdapSearchScope::Base => "Base",
                LdapSearchScope::OneLevel => "OneLevel",
                LdapSearchScope::Subtree => "Subtree",
            },
            self.attrs.clone().join(", ")
        ).as_str());
        out.push_str(format!("filter: {}", self.filter.format()).as_str());

        return out 
    }
}

fn filter_attrs(attrs: &Vec<String>, scope: &Vec<LdapPartialAttribute>) -> Vec<LdapPartialAttribute> {
    if attrs.contains(&"*".to_string()) {
        return scope.clone();
    }

    return scope.clone().into_iter().filter(|e| attrs.contains(&e.atype)).collect::<Vec<LdapPartialAttribute>>();
}

impl LdapSession {
    pub fn do_bind(&mut self, sbr: &SimpleBindRequest) -> LdapMsg {
        if sbr.dn == "cn=Directory Manager" && sbr.pw == "password" {
            sbr.gen_success()
        } else if sbr.dn == "" && sbr.pw == "" {
            sbr.gen_success()
        } else if sbr.dn == "cn=user01,ou=users,dc=example,dc=org" && sbr.pw == "user01" {
            sbr.gen_success()
        } else if sbr.dn == "cn=user01,ou=users,dc=example,dc=org" && sbr.pw == "user01" {
            sbr.gen_success()
        } else if sbr.dn == "TEST" && sbr.pw == "TEST" {
            sbr.gen_success()
        } else {
            sbr.gen_invalid_cred()
        }
    }

    pub fn old_do_search(&mut self, lsr: &SearchRequest) -> Vec<LdapMsg> {
        println!("new request");
        vec![
            lsr.gen_result_entry(LdapSearchResultEntry {
                dn: "".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "objectClass".to_string(),
                        vals: vec!["top".to_string()]
                    },
                    LdapPartialAttribute {                     
                        atype: "namingContexts".to_string(),
                        vals: vec!["dc=example,dc=org".to_string()],
                    },
                ]
            }),

            // Root object
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
            }),

            // ou=users,dc=example,dc=org
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
            }),

            // cn=readers,ou=users,dc=example,dc=org
            lsr.gen_result_entry(LdapSearchResultEntry {
                dn: "cn=readers,ou=users,dc=example,dc=org".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "objectClass".to_string(),
                        vals: vec!["groupOfNames".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec!["readers".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "member".to_string(),
                        vals: vec!["cn=user01,ou=users,dc=example,dc=org".to_string(), "cn=user02,ou=users,dc=example,dc=org".to_string()]
                    },
                ]
            }),

            // cn=user01,ou=users,dc=example,dc=org
            lsr.gen_result_entry(LdapSearchResultEntry {
                dn: "cn=user01,ou=users,dc=example,dc=org".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "objectClass".to_string(),
                        vals: vec!["inetOrgPerson".to_string(), "posixAccount".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec!["user01".to_string(), "User1".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "gidNumber".to_string(),
                        vals: vec!["1000".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "uid".to_string(),
                        vals: vec!["user01".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "uidNumber".to_string(),
                        vals: vec!["1000".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "userPassword".to_string(),
                        vals: vec!["user01".to_string()]
                    },
                ]
            }),

            // cn=user02,ou=users,dc=example,dc=org
            lsr.gen_result_entry(LdapSearchResultEntry {
                dn: "cn=user02,ou=users,dc=example,dc=org".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "objectClass".to_string(),
                        vals: vec!["inetOrgPerson".to_string(), "posixAccount".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec!["user02".to_string(), "User2".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "gidNumber".to_string(),
                        vals: vec!["2000".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "uid".to_string(),
                        vals: vec!["user02".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "uidNumber".to_string(),
                        vals: vec!["2000".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "userPassword".to_string(),
                        vals: vec!["user02".to_string()]
                    },
                ]
            }),

            lsr.gen_success()
        ]
    }

    pub fn new_do_search(&mut self, lsr: &SearchRequest) -> Vec<LdapMsg> {
        let suffix_lower = lsr.base.to_ascii_lowercase();
        let base_lower = "ou=users,dc=example,dc=com".to_string();

        let mut cn_base_search: Option<String> = None;

        if lsr.scope == LdapSearchScope::Base {
            if lsr.base.is_empty() {
                return vec![
                    lsr.gen_result_entry(LdapSearchResultEntry {
                        dn: "".to_owned(),
                        attributes: vec![
                            LdapPartialAttribute {
                                atype: "objectClass".to_owned(),
                                vals: vec!["dcObject".to_string(), "top".to_owned()],
                            },
                            LdapPartialAttribute {
                                atype: "namingContexts".to_owned(),
                                vals: vec!["ou=users,dc=example,dc=com".to_string()],
                            },
                            LdapPartialAttribute {                     
                                atype: "dc".to_string(),
                                vals: vec!["example".to_string()],
                            },
                            LdapPartialAttribute {                     
                                atype: "o".to_string(),
                                vals: vec!["example".to_string()],
                            },
                        ],
                    }),
                    lsr.gen_success(),
                ];
            } else if suffix_lower.ends_with(&format!(",{}", base_lower)) {
                return vec![lsr.gen_success()];
            } else if base_lower == suffix_lower {
                let leaf_short = suffix_lower[0..suffix_lower.find("=").unwrap()].to_owned();
                let leaf_name = suffix_lower
                    [(suffix_lower.find("=").unwrap() + 1)..suffix_lower.find(",").unwrap()]
                    .to_owned();
                let object_class = match &leaf_short as &str {
                    "dc" => "dcObject".to_owned(),
                    "ou" => "organizationalUnit".to_owned(),
                    _ => {
                        println!("The base dn type \"{}\" is not implemented", leaf_short);
                        return vec![
                            lsr.gen_error(LdapResultCode::Other, "Not implemented".to_owned())
                        ];
                    }
                };
                return vec![
                    lsr.gen_result_entry(LdapSearchResultEntry {
                        dn: suffix_lower.to_owned(),
                        attributes: vec![
                            LdapPartialAttribute {
                                atype: "objectClass".to_owned(),
                                vals: vec![object_class],
                            },
                            LdapPartialAttribute {
                                atype: leaf_short,
                                vals: vec![leaf_name],
                            },
                            LdapPartialAttribute {
                                atype: "hasSubordinates".to_owned(),
                                vals: vec!["TRUE".to_owned()],
                            },
                            LdapPartialAttribute {
                                atype: "entryDN".to_owned(),
                                vals: vec![suffix_lower.to_owned()],
                            },
                        ],
                    }),
                    lsr.gen_success(),
                ];
            } else if base_lower.ends_with(&format!(",{}", &suffix_lower)) {
                let ident = &base_lower[0..base_lower.len() - suffix_lower.len() - 1];
                // TODO this can be improved
                let ident_split: Vec<&str> = ident.split("=").take(3).collect();
                if ident.contains(",") || ident_split.len() != 2 || ident_split[0] != "cn" {
                    return vec![lsr.gen_error(LdapResultCode::NoSuchObject, "".to_owned())];
                }
                cn_base_search = Some(ident_split[1].to_owned());
            } else {
                return vec![lsr.gen_error(LdapResultCode::NoSuchObject, String::new())];
            }
        } else {
            return vec![lsr.gen_success()];
        }

        match cn_base_search {
            Some(cn) => {
                println!("BaseSearch: {}", cn);

                return vec![
                    lsr.gen_result_entry(LdapSearchResultEntry {
                        dn: "".to_owned(),
                        attributes: vec![
                            LdapPartialAttribute {
                                atype: "objectClass".to_owned(),
                                vals: vec!["users".to_owned()],
                            },
                            LdapPartialAttribute {
                                atype: "password".to_owned(),
                                vals: vec!["ello".to_string()],
                            },
                        ],
                    }),
                    lsr.gen_success(),
                ];
            }
            None => {
                return vec![lsr.gen_error(LdapResultCode::SizeLimitExceeded, "elp".to_string())];
            }
        }

    }

    pub fn do_search(&mut self, lsr: &SearchRequest) -> Vec<LdapMsg> {
        println!("{}", lsr.format());

        let mut out:Vec<LdapMsg> = Vec::new();

        if lsr.scope == LdapSearchScope::Base {
            if lsr.base.is_empty() {
                out = vec![lsr.gen_result_entry(LdapSearchResultEntry{
                    dn: "".to_string(),
                    attributes: filter_attrs(&lsr.attrs, &self.base_attrs)
                }), lsr.gen_success()];

            } else if lsr.base == "cn=Subschema" {
                out = vec![lsr.gen_success()];

            } else if lsr.base == self.dn {
                out = vec![lsr.gen_result_entry(LdapSearchResultEntry {
                    dn: self.dn.to_owned(),
                    attributes: filter_attrs(&lsr.attrs, &self.dn_attrs)
                }), lsr.gen_success()];

            } else if lsr.base == format!("ou={},{}", &self.ou, &self.dn) {
                out = vec![lsr.gen_result_entry(LdapSearchResultEntry {
                    dn: format!("ou={},{}", &self.ou, &self.dn),
                    attributes: filter_attrs(&lsr.attrs, &self.ou_attrs)
                })];
            } else if lsr.base.contains(&self.dn) {
                // Is a subtree

            } else {
                // hmmmmm
                println!("hmmmmm kinda sus");
                out = vec![lsr.gen_error(LdapResultCode::NoSuchObject, format!("The object {} does not exist", &lsr.base))];

            }
        } else if lsr.scope == LdapSearchScope::OneLevel {
            if lsr.base == self.dn {
                out = vec![lsr.gen_result_entry(LdapSearchResultEntry {
                    dn: format!("ou={},{}", &self.ou, &self.dn),
                    attributes: filter_attrs(&lsr.attrs, &self.ou_attrs)
                }), lsr.gen_success()];
            } else if lsr.base == format!("ou={},{}", &self.ou, &self.dn) {
                // no users have been added yet
            }
        } else {
            println!("PANIC");
            out = vec![lsr.gen_error(LdapResultCode::OperationsError, "Unsupported opperation".to_string())];
        }

        println!("Exiting with {} messages", out.len());

        if out.len() == 0 {
            println!("DID I JUST SAID 0??? PANIC !!!!!!");  // lol
            out = vec![lsr.gen_error(LdapResultCode::OperationsError, "This is kinda embarassing...".to_string())];
        }

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

    let dn = "dc=aarys,dc=fr".to_string();

    let mut session = LdapSession {
        dn: dn.to_owned(),
        ou: "users".to_string(),
        base_attrs: vec![
            LdapPartialAttribute {
                atype: "subschemaSubentry".to_string(),
                vals: vec![ "cn=Subschema".to_string() ]
            },
            LdapPartialAttribute {
                atype: "namingContexts".to_string(),
                vals: vec![ dn.to_owned() ]
            },
            LdapPartialAttribute {
                atype: "supportedLDAPVersion".to_string(),
                vals: vec![ "3".to_string()]
            },
            LdapPartialAttribute {
                atype: "vendorName".to_string(),
                vals: vec![ "github.com/aaryswastaken".to_string()]
            },
            LdapPartialAttribute {
                atype: "vendorVersion".to_string(),
                vals: vec![ "1".to_string()]
            },
        ],
        dn_attrs: vec![
            LdapPartialAttribute {
                atype: "objectClass".to_string(),
                vals: vec![ "dcObject".to_string(), "top".to_string(), "organization".to_string() ]
            },
            LdapPartialAttribute {
                atype: "dc".to_string(),
                vals: vec![ "aarys".to_string() ]
            }
        ],
        ou_attrs: vec![
            LdapPartialAttribute {
                atype: "objectClass".to_string(),
                vals: vec!["organizationalUnit".to_string()]
            },
            LdapPartialAttribute {
                atype: "ou".to_string(),
                vals: vec!["users".to_string()]
            }
        ]
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