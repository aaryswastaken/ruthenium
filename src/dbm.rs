// Database mannager (this is gonna be fun lol)

use std::fs;

use ldap3_proto::simple::*;

pub struct Whitelist {
    pub whitelisted: Vec<User>,
    pub dc: String
}

pub struct User {
    pub username: String,
    pub uid: i64
}

impl Whitelist {
    pub fn empty() -> Whitelist{
        Whitelist{whitelisted: vec![], dc: "".to_string()}
    }

    pub fn do_search(&mut self, lsr: &SearchRequest) -> Vec<LdapMsg> {
        let mut out: Vec<LdapMsg> = Vec::new();

        for user in self.whitelisted.iter_mut() {
            if format!("cn={},{}", user.username, self.dc) == lsr.base {
                out.push(user.gen_ldap_msg(self.dc.to_string(), lsr));
                break
            }
        }

        out.push(lsr.gen_success());

        return out
    }

    pub fn generate_ldap_entries(&mut self, lsr: &SearchRequest) -> Vec<LdapMsg> {
        let mut out = self.whitelisted.iter_mut().map(|user| user.gen_ldap_msg(self.dc.to_string(), lsr)).collect::<Vec<LdapMsg>>();
        out.push(lsr.gen_success());

        return out;
    }
}

impl User {
    pub fn gen_ldap_msg(&mut self, dc: String, lsr: &SearchRequest) -> LdapMsg {
        return lsr.gen_result_entry(LdapSearchResultEntry {
            dn: format!("cn={},{}", self.username, dc),
            attributes: vec![
                LdapPartialAttribute {
                    atype: "objectClass".to_string(),
                    vals: vec!["inetOrgPerson".to_string(), "posixAccount".to_string()]
                },
                LdapPartialAttribute {
                    atype: "cn".to_string(),
                    vals: vec![self.username.to_string()]
                },
                LdapPartialAttribute {
                    atype: "gidNumber".to_string(),
                    vals: vec![self.uid.to_string()]
                },
                LdapPartialAttribute {
                    atype: "uid".to_string(),
                    vals: vec![self.username.to_string()]
                },
                LdapPartialAttribute {
                    atype: "uidNumber".to_string(),
                    vals: vec![self.uid.to_string()]
                }
            ]
        })
    }
}

pub fn read_from_file(filename: String, dc: String) -> Whitelist {
    let content = fs::read_to_string(filename).expect("Something went wrong while trying to read the file");

    let whitelist = Whitelist{whitelisted: content.lines().enumerate().map(|(uid, name)| User{username: name.to_string(), uid: uid as i64}).collect::<Vec<User>>(), dc: dc};

    return whitelist
}