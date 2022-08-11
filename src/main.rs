use ldap3_proto::proto::LdapOp;
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
use ldap3_proto::LdapCodec;
use ldap3_proto::simple::LdapFilter::*;

use reqwest::Client;

use crate::dbm::DynamicObject;

mod dbm;

struct AuthError;

async fn authenticate(client: &Client, username: String, password: String) -> Result<(), AuthError> {
    println!("Will try to authenticate {} against plex SSO", &username);

    let res = client
        .post("https://plex.tv/users/sign_in.xml")
        .header("X-Plex-Device", "RutheniumProxy")
        .header("X-Plex-Model", "2,3")
        .header("X-Plex-Client-Identifier", "001")
        .header("X-Plex-Platform", "Rust")
        .header("X-Plex-Client-Platform", "Rust")
        .header("X-Plex-Client-Profile-Extra", "add-transcode-target(type=MusicProfile&context=streaming&protocol=hls&container=mpegts&audioCodec=aac)+add-transcode-target(type=videoProfile&context=streaming&protocol=hls&container=mpegts&videoCodec=h264&audioCodec=aac,mp3&replace=true)")
        .header("X-Plex-Product", "PlexConnect")
        .header("X-Plex-Version", "1.0.0")
        .basic_auth(username, Some(password))
        .send().await;
    
    match res {
        Ok(response) => {
            if response.status().is_success() {
                println!("Success");
                return Ok(())
            } else {
                println!("Request status: {}", response.status());
                return Err(AuthError)
            }
        },
        Err(_e) => return Err(AuthError)
    }
}

pub struct LdapSession {
    manager: dbm::ObjectManager,
    http_client: Client,
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
    pub async fn do_bind(&mut self, sbr: &SimpleBindRequest) -> LdapMsg {
        if sbr.dn == "cn=Directory Manager" && sbr.pw == "password" {
            sbr.gen_success()
        } else {
            if sbr.dn.contains(&self.manager.users_dn) {
                return match self.manager.fetch_user_from_dn(&sbr.dn) {
                    Some(user) => {
                        // Will try to authenticate user
                        println!("Found the user {}, will try to authenticate", &sbr.dn);

                        match authenticate(&self.http_client, user.username.to_owned(), sbr.pw.clone()).await {
                            Ok(_) => sbr.gen_success(),
                            Err(_) => sbr.gen_invalid_cred()
                        }
                    },
                    None => sbr.gen_invalid_cred()
                };
            }

            sbr.gen_invalid_cred()
        }
    }

    pub fn do_search(&mut self, lsr: &SearchRequest) -> Vec<LdapMsg> {
        println!("{}", lsr.format());

        let mut out:Vec<LdapMsg> = Vec::new();

        if lsr.scope == LdapSearchScope::Base {
            if lsr.base.is_empty() {
                // Client wants informations about root entity
                out = vec![lsr.gen_result_entry(LdapSearchResultEntry{
                    dn: "".to_string(),
                    attributes: filter_attrs(&lsr.attrs, &self.base_attrs)
                }), lsr.gen_success()];

            } else if lsr.base == "cn=Subschema" {
                // Client wants something that I am too lazy to implement
                out = vec![lsr.gen_success()];

            } else if lsr.base == self.manager.dn {
                // Client wants informations about our main thinggy
                out = vec![lsr.gen_result_entry(LdapSearchResultEntry {
                    dn: self.manager.dn.to_owned(),
                    attributes: filter_attrs(&lsr.attrs, &self.dn_attrs)
                }), lsr.gen_success()];

            } else if lsr.base == self.manager.users_dn {
                // Clients wants information about user group (ou=ou,dn)
                out = vec![lsr.gen_result_entry(LdapSearchResultEntry {
                    dn: self.manager.users_dn.to_owned(),
                    attributes: filter_attrs(&lsr.attrs, &self.ou_attrs)
                }), lsr.gen_success()];
            } else if lsr.base.contains(&self.manager.dn) {
                // Is a subtree, probably a user

                // checking if it's a user 
                out = match self.manager.fetch_user_from_dn(&lsr.base) {
                    Some(user) => vec![lsr.gen_result_entry(user.get_ldap_entry(&self.manager.ou, &self.manager.dn)), lsr.gen_success()],
                    None => vec![lsr.gen_error(LdapResultCode::NoSuchObject, format!("The user {} does not exist", &lsr.base))]
                };
            } else {
                // Client does shit
                println!("hmmmmm kinda sus");
                out = vec![lsr.gen_error(LdapResultCode::NoSuchObject, format!("The object {} does not exist", &lsr.base))];

            }
        } else if lsr.scope == LdapSearchScope::OneLevel {
            // Client would want to know the children of ...
            if lsr.base.is_empty() {
                // sending root 
                let new_lsr = SearchRequest {msgid: lsr.msgid, base: self.manager.dn.to_owned(), scope: LdapSearchScope::Base, filter: lsr.filter.to_owned(), attrs: lsr.attrs.to_owned()};
                out = self.do_search(&new_lsr);
            } else if lsr.base == self.manager.dn {
                // our dn (sending our ou=users because it's the child)
                let new_lsr = SearchRequest {msgid: lsr.msgid, base: self.manager.users_dn.to_owned(), scope: LdapSearchScope::Base, filter: lsr.filter.to_owned(), attrs: lsr.attrs.to_owned()};
                out = self.do_search(&new_lsr);
            } else if lsr.base == self.manager.users_dn {
                // out ou (sending users)
                out = self.manager.get_all_ldap_entries(lsr);
                out.push(lsr.gen_success());
            } else if lsr.base.contains(&self.manager.users_dn) {
                out = match self.manager.fetch_user_from_dn(&lsr.base) {
                    Some(_user) => vec![lsr.gen_success()], // there is nothing to show but no error neither
                    None => vec![lsr.gen_error(LdapResultCode::NoSuchObject, "This object doesn't exists".to_string())] // there is no object so no sub objects
                };
            } else {
                out = vec![lsr.gen_error(LdapResultCode::NoSuchObject, "This object doesn't exists".to_string())];
            }
        } else if lsr.scope == LdapSearchScope::Subtree {
            // That's the part where the headache begins

            out = self.do_rescursive_search(lsr, 0);

            if out.len() > 0 {
                out.push(lsr.gen_success());
            } else {
                out.push(lsr.gen_error(LdapResultCode::NoSuchObject, "This is embarassing".to_string()));
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

        return self.apply_filter(out, &lsr.filter);
    }

    fn apply_filter(&mut self, msgs: Vec<LdapMsg>, filter: &LdapFilter) -> Vec<LdapMsg> {
        let mut out: Vec<LdapMsg> = Vec::new();

        for msg in msgs.into_iter() {
            match msg.clone().op {
                LdapOp::SearchResultEntry(entry) => {
                    if self.does_result_matches_filter(&entry, filter) {
                        out.push(msg);
                    }
                }
                _ => {
                    out.push(msg);
                }
            }
        }

        return out;
    }

    // Another reccursive funtion LOL
    fn does_result_matches_filter(&mut self, entry: &LdapSearchResultEntry, root_filter: &LdapFilter) -> bool {
        match root_filter {
            And(filters) => filters.iter().all(|f| self.does_result_matches_filter(entry, f)),
            Or(filters) => filters.iter().any(|f| self.does_result_matches_filter(entry, f)),
            Not(filter) => !self.does_result_matches_filter(entry, filter),
            Equality(str_a, str_b) => entry.attributes.iter().filter(|attr| attr.atype == *str_a).any(|attr| attr.vals.iter().any(|val| val == str_b)),
            Substring(str, substr_filter) => {
                return match &substr_filter.initial {
                    Some(s) => str.starts_with(s),
                    None => true
                } && match &substr_filter.final_ {
                    Some(s) => str.ends_with(s),
                    None => true
                } && substr_filter.any.clone().into_iter().any(|s| str.contains(&s));
            },
            //GE
            //LE
            Present(str_a) => entry.attributes.clone().into_iter().any(|attr| attr.atype == *str_a),
        }
    }

    fn do_rescursive_search(&mut self, lsr: &SearchRequest, depth: i32) -> Vec<LdapMsg> {
        if depth > 10 {
            println!("Max depth has been reached, exiting");
            return vec![];
        }

        let mut temp:Vec<LdapSearchResultEntry> = Vec::new();

        let mut new_lsr = lsr.clone();
        new_lsr.scope = LdapSearchScope::OneLevel;
        let next_level = self.do_search(&new_lsr);

        let mut abort: bool = false;

        if next_level.len() > 0 {
            for result in next_level.into_iter() {
                match result.op { // there is a problem in borrowing here
                    LdapOp::SearchResultEntry(entry) => {
                        temp.push(entry);
                    },
                    LdapOp::SearchResultDone(res) => {
                        match res.code {
                            LdapResultCode::Success => {
                                // do nothing lol
                            },
                            _ => {
                                abort = true; // There is an error we don't need to process the information
                            }
                        };
                    },
                    _ => {
                        // hmmmmmm
                        abort = true;
                        println!("There is something strange here kinda sus ngl");
                    }
                }
            }
        } else {
            // ++++++++++++++++ PANIK ++++++++++++++++
            println!("Panix please elp");
            abort = true; // lol
        }

        let mut out = Vec::new();

        if !abort {
            for entry in temp.into_iter() {
                out.push(lsr.gen_result_entry(entry.clone()));

                let mut new_lsr = lsr.clone();
                new_lsr.base = entry.dn;

                println!("Going one level deeper with {}", &new_lsr.base);
                out.append(&mut self.do_rescursive_search(&new_lsr, depth + 1));
            }   
        } else {
            println!("Aborting on recursive search (dn: {}, depth: {})", &lsr.base, depth);
        }

        return out;
    }

    pub fn do_whoami(&mut self, wr: &WhoamiRequest) -> LdapMsg {
        wr.gen_success(format!("dn: {}", self.manager.dn).as_str())
    }
}

async fn handle_client(socket: TcpStream, _paddr: net::SocketAddr) {
    // Configure the codec etc.
    let (r, w) = tokio::io::split(socket);
    let mut reqs = FramedRead::new(r, LdapCodec);
    let mut resp = FramedWrite::new(w, LdapCodec);

    let dn = "dc=aarys,dc=fr".to_string();
    let ou = "users".to_string();

    let mut session = LdapSession {
        manager: dbm::ObjectManager::initialise("./whitelist".to_string(), dn.to_owned(), ou.to_owned()),
        http_client: Client::new(),
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
            ServerOps::SimpleBind(sbr) => vec![session.do_bind(&sbr).await],
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

    println!("PROD =============== started ldap://0.0.0.0:12345 ...");
    tokio::signal::ctrl_c().await.unwrap();
}