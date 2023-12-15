use std::collections::HashMap;
use std::hash::Hash;
use log::info;
// use std::sync::{Arc, Mutex};
// use rayon::prelude::*;

use tfhe::prelude::*;
use tfhe::FheBool;

use crate::ciphertext::{FheString, PaddingOptions};

pub enum Pattern {
    Clear(String),
    Encrypted(FheString),
}

impl Pattern {
    fn has_padding(&self) -> bool {
        match self {
            Pattern::Clear(_) => false,
            Pattern::Encrypted(pattern) => {
                pattern.has_padding()
            },
        }
    }

    fn len(&self) -> usize {
        match self {
            Pattern::Clear(pattern) => pattern.len(),
            Pattern::Encrypted(pattern) => {
                pattern.chars.len()
            },
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum PatternId {
    Zero,
    Index(usize),
    Byte(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Execution {
    Eq(usize, PatternId),
    And { l_res: Box<Execution>, r_res:  Box<Execution> },
    Or { l_res: Box<Execution>, r_res:  Box<Execution> },
    PatternMatch { c_pos: usize, p_pos: usize },
}

#[derive(Debug, Clone)]
enum ExecutionTree {
    Leaf(Execution),
    Node {
        op: Execution,
        left: Box<ExecutionTree>,
        right: Box<ExecutionTree>,
    },
}

pub struct SimpleEngine {
    // cache: Arc<Mutex< HashMap<Execution, Option<FheBool>> >>,
    cache: HashMap<Execution, Option<FheBool>>,
    pm_cache: HashMap<Execution, Execution>,

    // ops_count: usize,
    // cache_hits: usize,
}

impl SimpleEngine {
    pub fn new() -> Self {
        Self {
            // cache: Arc::new(Mutex::new(HashMap::new())),
            cache: HashMap::new(),
            pm_cache: HashMap::new(),

            // ops_count: 0,
            // cache_hits: 0,
        }
    }

    pub fn has_match(&mut self, content: &FheString, pattern: &Pattern, match_options: MatchingOptions) -> FheBool {
        if pattern.has_padding() {
            panic!("Padding not supported for the pattern.");
        }
        let full_match =  match_options.sof && match_options.eof;
        if content.chars.len() < pattern.len() || (!content.has_padding() && full_match && content.chars.len() != pattern.len()) {
            return FheBool::encrypt_trivial(false);
        }

        let final_op = self.build_execution_plan(content, pattern, match_options);

        let mut remaining_ops: Vec<Execution> = self.cache.keys().map(|k| k.clone()).collect();
        let mut prev_len = remaining_ops.len() + 1;

        while remaining_ops.len() < prev_len {
            prev_len = remaining_ops.len();
            remaining_ops = remaining_ops.iter()
                .map(|execution, | {
                    if let Some(_) = self.cache.get(execution).unwrap() {
                        return vec![];
                    }
                    let new_res = match execution {
                        Execution::Eq(c_pos, p_id) => match p_id {
                            PatternId::Zero => Some(content.chars[*c_pos].byte.eq(0)),
                            PatternId::Byte(b) => Some(content.chars[*c_pos].byte.eq(*b)),
                            PatternId::Index(p_pos) => {
                                if let Pattern::Encrypted(p) = pattern {
                                    Some(content.chars[*c_pos].byte.eq(p.chars[*p_pos].byte.clone()))
                                } else {
                                    panic!("Unexpected Clear pattern");
                                }
                            },
                        },
                        Execution::And { l_res, r_res } =>
                            match (self.cache.get(&*l_res), self.cache.get(&*r_res)) {
                                (Some(Some(l)), Some(Some(r))) => Some(l & r),
                                _ => None,
                        },
                        Execution::Or { l_res, r_res } =>
                        match (self.cache.get(&*l_res), self.cache.get(&*r_res)) {
                            (Some(Some(l)), Some(Some(r))) => Some(l | r),
                            _ => None,
                    },
                        Execution::PatternMatch { .. } => None,
                    };

                    if let Some(ref res) = new_res {
                        let _ = self.cache.get_mut(execution).unwrap().insert(res.clone());
                        // If there is a pattern match corresponding to this execution, set its result
                        if let Some(pm_exec) = self.pm_cache.get(execution) {
                            let _ = self.cache.get_mut(pm_exec).unwrap().insert(res.clone());
                        }
                        return vec![];
                    }
                    vec![execution.clone()]
                })
                .flatten()
                .collect();
        }
        if remaining_ops.len() > 0 {
            panic!("Could not compute {} remaining operations.", remaining_ops.len());
        }
        info!("Completed {} FHE operations.", self.cache.len());
        self.cache.get(&final_op).unwrap().clone().unwrap()
    }

    fn build_execution_plan(&mut self, content: &FheString, pattern: &Pattern, match_options: MatchingOptions) -> Execution {
        let mut final_op = Execution::PatternMatch { c_pos: 0, p_pos: 0 };
        let mut match_candidates: Vec<(usize, usize)> = if match_options.sof {
            vec![(0, 0)]
        } else {
            let max_start = content.chars.len() - pattern.len();
            if max_start > 0 {
                let nodes = self.build_leaves(0, max_start, PatternId::Index(0), "or");
                let root = self.build_bitwise_execution_tree(nodes, "or");
                final_op = self.insert_execution_tree(root);
                (0..=max_start).map(|c_pos| (c_pos, 0)).collect()
            } else {
                vec![(0, 0)]
            }
        };

        while match_candidates.len() > 0 {
            let (c_pos, p_pos) = match_candidates.pop().unwrap();
            let pattern_match = Execution::PatternMatch { c_pos, p_pos };
            let remain_c = content.chars.len() - c_pos;
            let remain_p = pattern.len() - p_pos;

            if self.cache.contains_key(&pattern_match) {
                continue
            }

            let mut maybe_l_res: Option<Execution> = None;
            if remain_p > 0 {
                let p_id = match pattern {
                    Pattern::Clear(ref p) => PatternId::Byte(p.as_bytes()[p_pos]),
                    Pattern::Encrypted(_) => PatternId::Index(p_pos),
                };
                let l_res = self.consume_pattern(c_pos, p_pos, p_id, remain_c, remain_p, match_options, content.padding);
                self.cache.insert(l_res.clone(), None);
                maybe_l_res = Some(l_res);
                if remain_p > 1 {
                    match_candidates.push((c_pos + 1, p_pos + 1));
                }
            }
        
            // TODO remove (remain_p == 0 && content.padding.end) as it's dealt by the zero_suffix constraint
            let can_consume_zero = remain_c - 1 >= remain_p
                && ((p_pos == 0 && content.padding.start) || (p_pos > 0 && content.padding.middle) || (remain_p == 0 && content.padding.end));
            let mut maybe_r_res: Option<Execution> = None;
            if can_consume_zero {
                let r_res = self.consume_pattern(c_pos, p_pos, PatternId::Zero, remain_c, remain_p, match_options, content.padding);
                self.cache.insert(r_res.clone(), None);
                maybe_r_res = Some(r_res);
                match_candidates.push((c_pos + 1, p_pos));
            }

            let execution = match (maybe_l_res, maybe_r_res) {
                (Some(l_res), Some(r_res)) => {
                    let ex = Execution::Or { l_res: Box::new(l_res), r_res: Box::new(r_res) };
                    self.cache.insert(ex.clone(), None);
                    ex
                },
                (Some(l_res), None) => l_res,
                (None, Some(r_res)) => r_res,
                (None, None) => panic!("Could not build branch at ({c_pos}, {p_pos})."),
            };
            self.pm_cache.insert(execution, pattern_match.clone());
            self.cache.insert(pattern_match, None);
        }
        final_op
    }

    fn insert_execution_tree(&mut self, root: ExecutionTree) -> Execution {
        let mut nodes = vec![&root];
        while !nodes.is_empty() {
            nodes = nodes.into_iter().map(|node| {
                let mut children: Vec<&ExecutionTree> = vec![];
                let execution = match node {
                    ExecutionTree::Leaf(ex) => ex,
                    ExecutionTree::Node { op, left, right } => {
                        if let ExecutionTree::Leaf(Execution::PatternMatch { .. }) = **left {
                        } else {
                            children.push(left);
                        };
                        if let ExecutionTree::Leaf(Execution::PatternMatch { .. }) = **right {
                        } else {
                            children.push(right);
                        };
                        op
                    },
                };

                if self.cache.contains_key(execution) {
                    return vec![];
                }
                self.cache.insert(execution.clone(), None);

                children
            })
            .flatten()
            .collect();
        }

        match root {
            ExecutionTree::Node { op, .. } => op,
            ExecutionTree::Leaf(ex) => ex,
        }
    }

    fn build_bitwise_execution_tree(&self, mut nodes: Vec<ExecutionTree>, op_type: &str) -> ExecutionTree {
        let make_bitwise_op = |l_res: Execution, r_res: Execution| {
            match op_type {
                "and" => Execution::And { l_res: Box::new(l_res), r_res: Box::new(r_res) },
                "or" => Execution::Or { l_res: Box::new(l_res), r_res: Box::new(r_res) },
                s => panic!("Unexpected bitwise operation type '{s}'.")
            }
        };

        while nodes.len() > 1 {
            nodes = nodes
                .chunks(2)
                .map(|chunk| {
                    let left = chunk[0].clone();
                    let right = if chunk.len() > 1 {
                        chunk[1].clone()
                    } else {
                        chunk[0].clone()
                    };
                    let op = match (left.clone(), right.clone()) {
                        (ExecutionTree::Leaf(l_res), ExecutionTree::Leaf(r_res)) => make_bitwise_op(l_res, r_res),
                        (ExecutionTree::Node { op: l_res, .. }, ExecutionTree::Node { op: r_res, .. }) => make_bitwise_op(l_res, r_res),
                        _ => panic!("Unexpected Leaf and Node mismatch.")
                    };
                    ExecutionTree::Node { op, left: Box::new(left), right: Box::new(right) }
                })
                .collect();
        }

        nodes.pop().expect("Unexpected empty tree")
    }

    fn build_leaves(&mut self, c_start: usize, c_end: usize, p_id: PatternId, op_type: &str) -> Vec<ExecutionTree> {
        let make_leaf_op = |c_pos: usize| {
            match op_type {
                "and" => Execution::Eq(c_pos, p_id),
                "or" => if let PatternId::Index(p_pos) = p_id {
                    Execution::PatternMatch { c_pos, p_pos }
                } else {
                    panic!("Unexpected PatternId");
                },
                s => panic!("Unexpected bitwise operation type '{s}'.")
            }
        };

        // Make sure that the left nodes are even to increase cache hits
        let mut nodes: Vec<ExecutionTree> = if (c_end - c_start < 1) || (c_start % 2 > 0) {
            vec![ExecutionTree::Leaf(make_leaf_op(c_start))]
        } else {
            vec![]
        };
        nodes.extend((c_start..=c_end).map(|i| ExecutionTree::Leaf(make_leaf_op(i))));

        nodes
    }
    
    // A function that inserts all necessary executions to get the result of a pattern match starting at (c_pos, p_pos)
    // The p_id parameter can be Zero or a Byte if we consume the content character at c_pos as a Zero or the pattern byte at p_pos.
    // It returns the root Execution.
    fn consume_pattern(&mut self, c_pos: usize, p_pos: usize, p_id: PatternId, remain_c: usize, remain_p: usize, match_options: MatchingOptions, padding: PaddingOptions) -> Execution {
        let zero_prefixed = c_pos > 0 && p_pos == 0 && match_options.sof && padding.start;
        let zero_suffixed = remain_c > 1 && remain_p == 1 && match_options.eof && padding.end;

        let p_eq = Execution::Eq(c_pos, p_id);
        self.cache.insert(p_eq.clone(), None);

        let main_match = if remain_p < 2 {
            // This is the last char of the pattern to match
            p_eq
        } else {
            let pattern_match = match p_id {
                PatternId::Zero => Execution::PatternMatch { c_pos: c_pos + 1, p_pos },
                _ => Execution::PatternMatch { c_pos: c_pos + 1, p_pos: p_pos + 1 },
            };
            let ex_and = Execution::And {l_res: Box::new(p_eq), r_res: Box::new(pattern_match) };
            self.cache.insert(ex_and.clone(), None);
            ex_and
        };

        let mut insert_zero_range = |c_start, c_end| -> Execution {
            let nodes = self.build_leaves(c_start, c_end, PatternId::Zero, "and");
            let root = self.build_bitwise_execution_tree(nodes, "and");
            self.insert_execution_tree(root)
        };

        match (zero_prefixed, zero_suffixed) {
            (false, false) => main_match,
            (true, false) => {
                let zero_prefix_ex = insert_zero_range(0, c_pos - 1);
                let ex_and = Execution::And { l_res: Box::new(zero_prefix_ex), r_res: Box::new(main_match) };
                self.cache.insert(ex_and.clone(), None);
                ex_and
            },
            (false, true) => {
                let zero_suffix_ex = insert_zero_range(c_pos + 1,  c_pos + remain_c - 1);
                let ex_and = Execution::And { l_res: Box::new(main_match), r_res: Box::new(zero_suffix_ex) };
                self.cache.insert(ex_and.clone(), None);
                ex_and
            },
            (true, true) => {
                let zero_prefix_ex = insert_zero_range(0, c_pos - 1);
                let zero_suffix_ex = insert_zero_range(c_pos + 1,  c_pos + remain_c - 1);
                let ex_and = Execution::And { l_res: Box::new(zero_prefix_ex), r_res: Box::new(main_match) };
                self.cache.insert(ex_and.clone(), None);

                let final_and = Execution::And { l_res: Box::new(ex_and), r_res: Box::new(zero_suffix_ex)  };
                self.cache.insert(final_and.clone(), None);
                final_and
            }
        }
    }
}


#[derive(Default, Debug, Copy, Clone)]
pub struct MatchingOptions {
    pub sof: bool,
    pub eof: bool,
}