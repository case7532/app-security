use std::collections::{HashMap, VecDeque};

/// Perform a topological sort on a dependency graph.
///
/// `deps` maps each node to the list of nodes it depends on (prerequisites).
/// Returns nodes in startup order (prerequisites first), or an error if a
/// circular dependency is detected or a dependency references an unknown node.
pub fn topological_sort(deps: &HashMap<String, Vec<String>>) -> Result<Vec<String>, String> {
    // Validate all dependencies reference known nodes and compute in-degrees.
    let mut in_degree: HashMap<String, usize> = HashMap::new();

    for (node, dependents) in deps {
        in_degree.entry(node.clone()).or_insert(0);
        for dep in dependents {
            if !deps.contains_key(dep) {
                return Err(format!("Dependency not found: {}", dep));
            }
            // Each dependency adds an incoming edge to `node`.
            *in_degree.entry(node.clone()).or_insert(0) += 1;
        }
    }

    // Seed the queue with all nodes that have in-degree 0 (no prerequisites).
    let mut queue: VecDeque<String> = VecDeque::new();
    for (node, &degree) in &in_degree {
        if degree == 0 {
            queue.push_back(node.clone());
        }
    }

    let mut order = Vec::new();

    // Kahn's algorithm: process nodes with no remaining prerequisites.
    while let Some(node) = queue.pop_front() {
        order.push(node.clone());

        // For every node that lists `node` as a prerequisite, decrement their
        // in-degree. If it reaches zero, they are ready to be started.
        for (other, dependents) in deps {
            if dependents.contains(&node) {
                if let Some(degree) = in_degree.get_mut(other) {
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push_back(other.clone());
                    }
                }
            }
        }
    }

    if order.len() != deps.len() {
        return Err("Circular dependency detected".to_string());
    }

    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_node() {
        let mut deps: HashMap<String, Vec<String>> = HashMap::new();
        deps.insert("a".to_string(), vec![]);
        let order = topological_sort(&deps).unwrap();
        assert_eq!(order, vec!["a"]);
    }

    #[test]
    fn test_chain() {
        let mut deps: HashMap<String, Vec<String>> = HashMap::new();
        deps.insert("c".to_string(), vec!["b".to_string()]);
        deps.insert("b".to_string(), vec!["a".to_string()]);
        deps.insert("a".to_string(), vec![]);
        let order = topological_sort(&deps).unwrap();
        assert_eq!(order, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_unknown_dependency() {
        let mut deps: HashMap<String, Vec<String>> = HashMap::new();
        deps.insert("a".to_string(), vec!["missing".to_string()]);
        assert!(topological_sort(&deps).is_err());
    }
}
