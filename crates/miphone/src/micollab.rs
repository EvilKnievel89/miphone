//! Client for the MiCollab server's JSON-RPC interface (`/ucs/json/JsonServlet`), as far as
//! the softphone needs it: the user's presence statuses ("Im Büro", "Nicht stören", ...).
//!
//! Requests are authenticated with the user's own login (HTTP basic auth), like the
//! MiCollab client does.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::MicollabConfig;
use crate::provision::{find_key, percent_decode};

/// One of the user's statuses.
#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    /// Identifier as the server sent it; passed back unchanged when selecting the status.
    pub id: Value,
    pub name: String,
    /// Chat state that goes with the status, e.g. `Idle`, `Away`, `Offline`.
    pub im_status: String,
    /// False if calls are not put through in this status (do not disturb).
    pub available_for_calls: bool,
}

impl Status {
    fn parse(v: &Value) -> Option<Status> {
        let name = v.get("name")?.as_str()?.to_string();
        let id = v.get("id").filter(|id| !id.is_null())?.clone();
        // A list with one entry may arrive as a bare value instead of an array.
        let availabilities = v.get("availabilities").and_then(|a| a.get("availability"));
        let available_for_calls = match availabilities {
            Some(Value::Array(items)) => items.iter().any(|a| a.as_str() == Some("AvailableCall")),
            Some(Value::String(one)) => one == "AvailableCall",
            // Without the field we cannot tell; do not claim "do not disturb".
            _ => true,
        };
        Some(Status { id, name, im_status: v.get("imStatus").and_then(Value::as_str).unwrap_or("").to_string(), available_for_calls })
    }
}

/// A phone number of a contact with its label (e.g. "Work", "Mobile").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phone {
    pub number: String,
    pub label: String,
}

/// An entry of the corporate directory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Contact {
    pub id: String,
    pub first_name: String,
    pub last_name: String,
    pub company: String,
    pub department: String,
    pub email: String,
    pub phones: Vec<Phone>,
    /// Identity on the event channel under which the contact's presence is reported.
    pub presence_id: Option<String>,
}

impl Contact {
    /// "First Last", or whichever part exists.
    pub fn name(&self) -> String {
        format!("{} {}", self.first_name, self.last_name).trim().to_string()
    }

    fn parse(v: &Value) -> Option<Contact> {
        let text = |key: &str| v.get(key).and_then(Value::as_str).unwrap_or("").trim().to_string();
        let id = id_text(v.get("id")?)?;
        let mut phones: Vec<Phone> = Vec::new();
        for p in nested(v, "phones", "phone") {
            // Numbers the user did not publish are not for dialling.
            if p.get("published").and_then(Value::as_bool) == Some(false) {
                continue;
            }
            let number = p.get("number").and_then(Value::as_str).unwrap_or("").trim().to_string();
            if !number.is_empty() && !phones.iter().any(|known| known.number == number) {
                phones.push(Phone { number, label: p.get("name").and_then(Value::as_str).unwrap_or("").to_string() });
            }
        }
        let emails = nested(v, "emails", "email");
        let preferred = emails.iter().find(|e| e.get("preferred").and_then(Value::as_bool) == Some(true)).or(emails.first());
        let email = preferred.and_then(|e| e.get("address")).and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| text("primaryEmail"));
        let presence_id = nested(v, "presences", "presence").first().and_then(|p| p.get("login")).and_then(Value::as_str).map(str::to_string);
        let department = Some(text("departmentName")).filter(|d| !d.is_empty()).unwrap_or_else(|| text("department"));
        Some(Contact { id, first_name: text("firstName"), last_name: text("lastName"), company: text("companyName"), department, email, phones, presence_id })
    }
}

/// What changed in the directory since a point in time.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ContactChanges {
    /// Ids of new or changed contacts (all contacts when asked without a timestamp).
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
    /// Marker to pass to the next request; opaque.
    pub timestamp: Value,
}

/// One of the user's contact groups (favourites and the like).
#[derive(Debug, Clone, PartialEq)]
pub struct Group {
    pub id: Value,
    pub name: String,
}

/// An id as text, whether the server sent a string or a number.
fn id_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The server wraps lists as `{"outer": {"inner": [...]}}`, sometimes without the inner level,
/// and a list with one entry may be a bare object.
fn nested<'a>(v: &'a Value, outer: &str, inner: &str) -> Vec<&'a Value> {
    let list = match v.get(outer) {
        Some(o) => o.get(inner).unwrap_or(o),
        None => return Vec::new(),
    };
    match list {
        Value::Array(items) => items.iter().collect(),
        Value::Null => Vec::new(),
        one => vec![one],
    }
}

/// The first list of objects found anywhere in an answer. Used where only the element
/// fields are known, not the name of the list.
fn first_object_list(v: &Value) -> Vec<&Value> {
    match v {
        Value::Array(items) if items.iter().any(Value::is_object) => items.iter().filter(|i| i.is_object()).collect(),
        Value::Array(items) => items.iter().flat_map(first_object_list).collect(),
        Value::Object(map) => {
            // A bare object with an id stands for a list with one entry.
            if map.contains_key("id") {
                return vec![v];
            }
            map.values().map(first_object_list).find(|l| !l.is_empty()).unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

/// What the event channel needs to know about the account.
#[derive(Debug, Clone, PartialEq)]
pub struct Account {
    /// Tenant the account belongs to, as the server sent it (may be absent).
    pub tenant: Value,
    pub contact_id: String,
    pub first_name: String,
    pub last_name: String,
    /// Identity under which the server reports our own presence (`sipUserID`). It ends in the
    /// server's internal name, which can differ from the name we connect to.
    pub presence_id: Option<String>,
}

pub struct Client {
    http: reqwest::Client,
    url: String,
    user: String,
    password: String,
}

impl Client {
    pub fn new(cfg: &MicollabConfig, password: &str) -> Result<Client> {
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(cfg.tls_insecure)
            .timeout(std::time::Duration::from_secs(20))
            .user_agent(cfg.user_agent.clone().unwrap_or_else(|| format!("miphone/{}", env!("CARGO_PKG_VERSION"))))
            .build()?;
        Ok(Client { http, url: format!("https://{}/ucs/json/JsonServlet", cfg.server), user: cfg.user.clone(), password: password.to_string() })
    }

    /// Calls the method named like the class, with a lower-case first letter.
    async fn rpc(&self, name: &str, req: Value) -> Result<Value> {
        let mut method = name.to_string();
        if let Some(first) = method.get_mut(..1) {
            first.make_ascii_lowercase();
        }
        self.rpc_as(name, &method, req).await
    }

    /// Calls one method and returns the `result` member of the answer.
    async fn rpc_as(&self, name: &str, method: &str, req: Value) -> Result<Value> {
        let body = json!({ "class": format!("com.mitel.ucs.ws.model.{name}"), "method": method, "req": req });
        let rsp = self
            .http
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.password))
            .header("Content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .with_context(|| format!("{name}: keine Verbindung zum MiCollab-Server"))?;
        let status = rsp.status().as_u16();
        if status == 401 {
            bail!("{name}: Anmeldung am MiCollab-Server abgelehnt");
        }
        let text = rsp.text().await?;
        parse_answer(name, status, &text)
    }

    pub async fn account(&self) -> Result<Account> {
        let result = self.rpc("GetAccountInfo", json!({})).await?;
        let contact_id = match result.get("contactID") {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            _ => bail!("GetAccountInfo: keine contactID in der Antwort"),
        };
        let text = |key: &str| result.get(key).and_then(Value::as_str).unwrap_or("").trim().to_string();
        Ok(Account { tenant: result.get("tenant").cloned().unwrap_or(Value::Null), contact_id, first_name: text("firstName"), last_name: text("lastName"), presence_id: Some(text("sipUserID")).filter(|id| !id.is_empty()) })
    }

    /// Ids of the directory entries changed since `since`; without it, of all entries.
    pub async fn changed_contacts(&self, since: Option<&Value>) -> Result<ContactChanges> {
        let req = match since {
            Some(ts) if !ts.is_null() => json!({ "timeStamp": ts }),
            _ => json!({}),
        };
        let result = self.rpc_as("SynchronizeContacts", "synchronizeDirectoryContacts", req).await?;
        Ok(parse_changes(&result))
    }

    /// Loads directory entries by id. The server is asked for moderate batches only.
    pub async fn contacts(&self, ids: &[String]) -> Result<Vec<Contact>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let result = self.rpc("GetDirectoryContacts", json!({ "contactIds": { "contactId": ids } })).await?;
        Ok(parse_contacts(&result))
    }

    pub async fn groups(&self) -> Result<Vec<Group>> {
        let result = self.rpc("GetCorpContactGroups", json!({})).await?;
        Ok(first_object_list(&result)
            .into_iter()
            .filter_map(|g| Some(Group { id: g.get("id").filter(|i| !i.is_null())?.clone(), name: g.get("name")?.as_str()?.to_string() }))
            .collect())
    }

    /// Ids of the contacts in a group.
    pub async fn group_members(&self, group: &Value) -> Result<Vec<String>> {
        let result = self.rpc("GetCorpContactGroupMembers", json!({ "corpGroupId": group })).await?;
        Ok(first_object_list(&result).into_iter().filter_map(|m| id_text(m.get("contactId").or_else(|| m.get("id"))?)).collect())
    }

    pub async fn statuses(&self) -> Result<Vec<Status>> {
        let result = self.rpc("GetStatuses", json!({})).await?;
        Ok(parse_statuses(&result))
    }

    pub async fn current_status(&self) -> Result<Status> {
        let result = self.rpc("GetCurrentStatus", json!({})).await?;
        Status::parse(&result).ok_or_else(|| anyhow!("GetCurrentStatus: unerwartete Antwort"))
    }

    pub async fn set_status(&self, id: &Value) -> Result<()> {
        self.rpc("SetCurrentStatusId", json!({ "statusId": id })).await.map(|_| ())
    }
}

fn parse_answer(name: &str, status: u16, text: &str) -> Result<Value> {
    // Some servers answer URL-encoded.
    let decoded;
    let text = if text.starts_with('%') {
        decoded = percent_decode(text);
        decoded.as_str()
    } else {
        text
    };
    // Calls without a return value may answer with an empty body.
    if text.trim().is_empty() && (200..300).contains(&status) {
        return Ok(Value::Null);
    }
    let answer: Value = serde_json::from_str(text).map_err(|_| anyhow!("{name}: Antwort (Status {status}) ist kein JSON"))?;
    if let Some(err) = find_key(&answer, "apperror").or_else(|| find_key(&answer, "servererror")) {
        bail!("{name}: der MiCollab-Server meldet einen Fehler: {err}");
    }
    if answer.get("status").and_then(Value::as_str) == Some("Login failed") {
        bail!("{name}: Anmeldung am MiCollab-Server fehlgeschlagen");
    }
    Ok(answer.get("result").cloned().unwrap_or(Value::Null))
}

fn parse_changes(result: &Value) -> ContactChanges {
    let ids = |key: &str| nested(result, key, "contactId").into_iter().filter_map(id_text).collect();
    ContactChanges { modified: ids("modified"), deleted: ids("deleted"), timestamp: result.get("timestamp").cloned().unwrap_or(Value::Null) }
}

fn parse_contacts(result: &Value) -> Vec<Contact> {
    let list = match result.get("contact") {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(one) if one.is_object() => vec![one],
        _ => Vec::new(),
    };
    list.into_iter().filter_map(Contact::parse).collect()
}

fn parse_statuses(result: &Value) -> Vec<Status> {
    match result.get("status") {
        Some(Value::Array(items)) => items.iter().filter_map(Status::parse).collect(),
        Some(one) => Status::parse(one).into_iter().collect(),
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUSES: &str = r#"{"result":{"status":[
        {"id":11,"name":"Im Büro","alternateName":"","availabilities":{"availability":["AvailableCall","AvailableIM","AvailableVideo"]},"imStatus":"Idle","isEditable":false},
        {"id":12,"name":"Nicht stören","availabilities":{"availability":["AvailableIM"]},"imStatus":"Away"},
        {"id":13,"name":"Abwesend","availabilities":{"availability":"AvailableCall"},"imStatus":"Offline"},
        {"name":"ohne Kennung"}
    ]}}"#;

    #[test]
    fn parses_status_list() {
        let result = parse_answer("GetStatuses", 200, STATUSES).unwrap();
        let list = parse_statuses(&result);
        assert_eq!(list.len(), 3, "entries without id are skipped");
        assert_eq!((list[0].name.as_str(), list[0].id.clone(), list[0].available_for_calls), ("Im Büro", json!(11), true));
        assert_eq!((list[1].im_status.as_str(), list[1].available_for_calls), ("Away", false));
        assert!(list[2].available_for_calls, "single value instead of array");
    }

    #[test]
    fn parses_current_status_and_single_entry_list() {
        let result = parse_answer("GetCurrentStatus", 200, r#"{"result":{"id":"a-7","name":"Mobil"}}"#).unwrap();
        let s = Status::parse(&result).unwrap();
        assert_eq!((s.id, s.name.as_str(), s.available_for_calls), (json!("a-7"), "Mobil", true));
        let single = parse_answer("GetStatuses", 200, r#"{"result":{"status":{"id":1,"name":"Im Büro"}}}"#).unwrap();
        assert_eq!(parse_statuses(&single).len(), 1);
        assert!(parse_statuses(&Value::Null).is_empty());
    }

    #[test]
    fn parses_directory_contacts() {
        let result = json!({"contact":[
            {"id":"c-1","firstName":"Erika","lastName":"Muster","companyName":"Beispiel GmbH","departmentName":"Vertrieb",
             "emails":{"email":[{"address":"alt@example.org","name":"Alt"},{"address":"erika@example.org","preferred":true}]},
             "phones":{"phone":[{"number":"1001","name":"Work"},{"number":"0170 1","name":"Mobile","published":false},{"number":"1001","name":"Softphone"},{"number":" ","name":"x"}]},
             "presences":{"presence":[{"login":"erika@example.org@mc.example.org","name":"IM"}]}},
            {"id":7,"firstName":null,"lastName":"Nur Nachname","phones":{"phone":{"number":"+49 30 1","name":"Work"}},"primaryEmail":"n@example.org"},
            {"firstName":"ohne","lastName":"Id"}
        ]});
        let list = parse_contacts(&result);
        assert_eq!(list.len(), 2);
        let erika = &list[0];
        assert_eq!((erika.name().as_str(), erika.company.as_str(), erika.department.as_str(), erika.email.as_str()), ("Erika Muster", "Beispiel GmbH", "Vertrieb", "erika@example.org"));
        assert_eq!(erika.phones, vec![Phone { number: "1001".into(), label: "Work".into() }], "unpublished, duplicate and empty numbers are dropped");
        assert_eq!(erika.presence_id.as_deref(), Some("erika@example.org@mc.example.org"));
        assert_eq!((list[1].id.as_str(), list[1].name().as_str(), list[1].email.as_str()), ("7", "Nur Nachname", "n@example.org"));
        assert_eq!(list[1].phones[0].number, "+49 30 1");
        // A single contact may arrive without the array.
        assert_eq!(parse_contacts(&json!({"contact":{"id":"x","lastName":"Solo"}})).len(), 1);
        assert!(parse_contacts(&Value::Null).is_empty());
    }

    #[test]
    fn parses_changes_and_lists() {
        let changes = parse_changes(&json!({"deletion":false,"modified":{"contactId":["a","b"]},"deleted":{"contactId":"z"},"timestamp":"2026-11-26T10:00:00.000Z"}));
        assert_eq!((changes.modified, changes.deleted, changes.timestamp), (vec!["a".to_string(), "b".into()], vec!["z".to_string()], json!("2026-11-26T10:00:00.000Z")));
        assert_eq!(parse_changes(&json!({})), ContactChanges::default());
        // Lists whose name we do not know: the first array of objects counts.
        let groups = json!({"corpContactGroup":[{"id":3,"name":"Favoriten"},{"id":4,"name":"Team"}]});
        assert_eq!(first_object_list(&groups).len(), 2);
        assert_eq!(first_object_list(&json!({"wrapper":{"member":{"id":"c-1"}}})).len(), 1);
        assert!(first_object_list(&json!({"count":0})).is_empty());
    }

    #[test]
    fn handles_errors_and_odd_answers() {
        assert!(parse_answer("X", 200, r#"{"apperror":"nope"}"#).unwrap_err().to_string().contains("nope"));
        assert!(parse_answer("X", 200, r#"{"status":"Login failed"}"#).is_err());
        assert!(parse_answer("X", 500, "<html>oops</html>").is_err());
        assert_eq!(parse_answer("SetCurrentStatusId", 200, "").unwrap(), Value::Null);
        assert_eq!(parse_answer("X", 200, "%7B%22result%22%3A+%7B%22a%22%3A1%7D%7D").unwrap(), json!({"a": 1}));
    }
}
