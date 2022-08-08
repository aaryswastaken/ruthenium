// Database mannager (this is gonna be fun lol)

use std::fs;

use ldap3_proto::proto::LdapSearchRequest;
use ldap3_proto::simple::*;
use ldap3_proto::simple::LdapFilter::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Whitelist {
    pub whitelisted: Vec<User>,
    pub dn: String
}

#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub username: String,
    pub uid: i64
}

pub trait DynamicObject {
    fn get_ldap_entry(&self, ou: &String, dn: &String) -> LdapSearchResultEntry;
}

pub trait ExtendedLdapSearchResultEntry {
    fn has_base(&mut self, base: &String) -> bool;
    fn matches_filter(&mut self, filter: &LdapFilter) -> bool;
    fn has_attribute(&mut self, attribute_name: &String) -> bool;
    fn get_attribute(&mut self, attribute_name: &String) -> Vec<String>;
}

impl DynamicObject for User {
    fn get_ldap_entry(&self, ou: &String, dn: &String) -> LdapSearchResultEntry {
        LdapSearchResultEntry {
            dn: format!("cn={},ou={},{}", self.username, ou, dn),
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
        }
    }
}

impl ExtendedLdapSearchResultEntry for LdapSearchResultEntry {
    fn has_base(&mut self, base: &String) -> bool {
        // return self.dn == base.clone() || (self.dn.split(",").collect::<Vec<&str>>().len() == base.split(",").collect::<Vec<&str>>().len() + 1 && self.dn.contains(base))
        return self.dn.contains(base);
    }

    fn matches_filter(&mut self, filter: &LdapFilter) -> bool {
        match filter {
            And(filters) => filters.iter().all(|e| self.matches_filter(&e)),
            Or(filters)  => filters.iter().any(|e| self.matches_filter(&e)),
            Not(not) => !self.matches_filter(&not),

            Equality(str1, str2) => {
                println!("Testing {} for {} attribute", self.dn, &str1);

                if self.has_attribute(&str1) {
                    println!("{} has it", self.dn);
                    if self.get_attribute(&str1).contains(str2) {
                        println!("Returns true"); true
                    } else {
                        println!("Returns false"); false
                    }
                } else {
                    false
                }},
            Substring(_str1, _idk) => true,  // ?????????????????????????????????????????

            Present(str1) => self.has_attribute(&str1)
        }
    }

    fn has_attribute(&mut self, attribute_name: &String) -> bool {
        self.attributes.clone().into_iter().any(|attribute| attribute.atype.to_ascii_lowercase() == attribute_name.to_ascii_lowercase())
    }

    fn get_attribute(&mut self, attribute_name: &String) -> Vec<String> {
        self.attributes.clone().into_iter().filter(|attribute| attribute.atype.to_ascii_lowercase() == attribute_name.to_ascii_lowercase()).map(|a| a.vals).flatten().collect::<Vec<String>>()
    }
}

pub struct ObjectManager {
    pub dn: String,
    pub ou: String,
    pub users_dn: String,
    pub dynamic_objects: Vec<User> // need to do this procedurally for every struct implementing DynamicObject trat
}

impl Whitelist {
    pub fn new() -> Whitelist{
        Whitelist{whitelisted: vec![], dn: "".to_string()}
    }

    pub fn read_from_file(filename: String, dn: String) -> Whitelist {
        let content = fs::read_to_string(filename).expect("Something went wrong while trying to read the file");
    
        let whitelist = Whitelist{whitelisted: content.lines().enumerate().map(|(uid, name)| User{username: name.to_string(), uid: uid as i64}).collect::<Vec<User>>(), dn: dn};
    
        return whitelist
    }
}

impl User {
}

impl ObjectManager {
    pub fn new(dn: String, ou: String) -> ObjectManager {
        ObjectManager {
            dn: dn.to_owned(),
            ou: ou.to_owned(),
            users_dn: format!("ou={},{}", &ou, &dn),
            dynamic_objects: vec![]
        }
    }

    pub fn initialise(filename: String, dc: String, ou: String) -> ObjectManager {
        let mut instance = ObjectManager::new(dc.to_owned(), ou.to_owned());

        instance.dynamic_objects = Whitelist::read_from_file(filename, dc.clone()).whitelisted;

        return instance;
    }

    pub fn get_all_ldap_entries(&mut self, lsr: &SearchRequest) -> Vec<LdapMsg> {
        return self.dynamic_objects.clone().iter_mut().map(|e| lsr.gen_result_entry(e.get_ldap_entry(&self.ou, &self.dn))).collect::<Vec<LdapMsg>>();
    }

    pub fn fetch_user_from_dn(&mut self, dn: &String) -> Option<User> {
        // This piece of code is disgusting, please read it at your own risk
        // Eye cleaning solution is recommended
        
        for user in self.dynamic_objects.clone().into_iter() {
            if user.get_ldap_entry(&self.ou, &self.dn).dn == *dn {
                return Some(user.clone())
            }
        }

        None
    }
}