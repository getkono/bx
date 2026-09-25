//! Check 2: every required declared value has an answer.
//!
//! The values are [`ResolvedValues::unset_required`]: the ones `bx init`
//! prompts for. A required value whose `default` failed only because another
//! value is unanswered is not listed, since answering the other one is the act
//! that clears both, and that one is listed.

use super::Finding;
use crate::config::values::{ResolvedValues, init_hint};

/// A finding for every required value with no answer, in declaration order.
#[must_use]
pub fn check(values: &ResolvedValues) -> Vec<Finding> {
    values
        .unset_required()
        .into_iter()
        .map(|decl| Finding {
            subject: format!("value {}", decl.name),
            origin: Some(decl.origin.clone()),
            note: format!(
                "is required and has no answer; {}",
                init_hint(&[decl.name.as_str()])
            ),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::config::parse_str;

    fn resolved(text: &str) -> ResolvedValues {
        let home = Path::new("/home/u");
        let config = parse_str(text, Path::new("/repo/bx.toml"), home).unwrap();
        ResolvedValues::resolve(config.values, &config.value_assignments, home).unwrap()
    }

    #[test]
    fn only_a_required_value_with_no_answer_of_its_own_is_a_finding() {
        let values = resolved(
            "[[value]]\nname = \"email\"\nkind = \"string\"\nrequired = true\n\
             [[value]]\nname = \"editor\"\nkind = \"string\"\n\
             [[value]]\nname = \"shell\"\nkind = \"string\"\nrequired = true\ndefault = \"zsh\"\n\
             [[value]]\nname = \"root\"\nkind = \"path\"\nrequired = true\n\
             [[value]]\nname = \"cache\"\nkind = \"path\"\nrequired = true\n\
             default = \"{{root}}/cache\"\n",
        );

        let findings = check(&values);

        let named: Vec<(&str, &str, usize)> = findings
            .iter()
            .map(|f| {
                (
                    f.subject.as_str(),
                    f.note.as_str(),
                    f.origin.as_ref().unwrap().line,
                )
            })
            .collect();
        assert_eq!(
            named,
            vec![
                (
                    "value email",
                    "is required and has no answer; run `bx init` to set email",
                    1
                ),
                (
                    "value root",
                    "is required and has no answer; run `bx init` to set root",
                    13
                ),
            ]
        );
    }

    #[test]
    fn an_answered_configuration_is_no_finding() {
        assert!(check(&resolved("[[value]]\nname = \"a\"\nkind = \"string\"\n")).is_empty());
    }
}
