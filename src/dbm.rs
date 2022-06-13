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

    pub fn do_search(lsr: &SearchRequest) -> Vec<LdapMsg> {
        return vec![];
    }

    pub fn generate_ldap_entries(&mut self, lsr: &SearchRequest) -> Vec<LdapMsg> {
        self.whitelisted.iter().map(|user| lsr.gen_result_entry(LdapSearchResultEntry {
            dn: format!("cn={},{}", user.username, self.dc),
            attributes: vec![
                LdapPartialAttribute {
                    atype: "objectClass".to_string(),
                    vals: vec!["inetOrgPerson".to_string(), "posixAccount".to_string()]
                },
                LdapPartialAttribute {
                    atype: "cn".to_string(),
                    vals: vec![user.username.to_string()]
                },
                LdapPartialAttribute {
                    atype: "gidNumber".to_string(),
                    vals: vec![user.uid.to_string()]
                },
                LdapPartialAttribute {
                    atype: "uid".to_string(),
                    vals: vec![user.username.to_string()]
                },
                LdapPartialAttribute {
                    atype: "uidNumber".to_string(),
                    vals: vec![user.uid.to_string()]
                }
            ]
        })).collect::<Vec<LdapMsg>>()
    }
}

pub fn read_from_file(filename: String, dc: String) -> Whitelist {
    let content = fs::read_to_string(filename).expect("Something went wrong while trying to read the file");

    let whitelist = Whitelist{whitelisted: content.lines().enumerate().map(|(uid, name)| User{username: name.to_string(), uid: uid as i64}).collect::<Vec<User>>(), dc: dc};

    return whitelist
}