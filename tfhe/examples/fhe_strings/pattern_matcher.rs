use log::info;
use rayon::prelude::*;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tfhe::prelude::*;
use tfhe::{FheBool, FheInt16, FheUint16};

use crate::ciphertext::{FheString, PaddingOptions};

#[derive(Clone)]
enum FheResult {
    Bool(FheBool),
    Uint(FheUint16)
}

#[derive(Default, Debug, Copy, Clone)]
pub enum MatchResult {
    #[default]
    Bool,
    StartIndex,
    RawStartIndex,
}

#[derive(Default, Debug, Copy, Clone)]
pub struct MatchingOptions {
    pub sof: bool, // Equivalent of the regex ^ special char
    pub eof: bool, // Equivalent of the regex $ special char
    pub result: MatchResult,
}

pub enum Pattern {
    Clear(String),
    Encrypted(FheString),
}

impl Pattern {
    fn has_padding(&self) -> bool {
        match self {
            Pattern::Clear(_) => false,
            Pattern::Encrypted(pattern) => pattern.has_padding(),
        }
    }

    fn len(&self) -> usize {
        match self {
            Pattern::Clear(pattern) => pattern.len(),
            Pattern::Encrypted(pattern) => pattern.chars.len(),
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
    And {
        l_res: Box<Execution>,
        r_res: Box<Execution>,
    },
    Or {
        l_res: Box<Execution>,
        r_res: Box<Execution>,
    },
    IndexMatch {
        c_pos: usize,
        p_pos: usize,
    },
    PatternMatch {
        c_pos: usize,
        p_pos: usize,
    },
    StartIndex {
        l_res: Box<Execution>,
        r_res: Box<Execution>,
    },
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
    cache: Arc<Mutex<HashMap<Execution, Option<FheResult>>>>,
    // cache: HashMap<Execution, Option<FheBool>>,
    // Mapping of an Or, And or Eq execution to its corresponding PatternMatch
    pm_cache: HashMap<Execution, Execution>,
    // ops_count: usize,
    // cache_hits: usize,
}

impl SimpleEngine {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            // cache: HashMap::new(),
            pm_cache: HashMap::new(),
            // ops_count: 0,
            // cache_hits: 0,
        }
    }

    pub fn has_match(
        &mut self,
        content: &FheString,
        pattern: &Pattern,
        match_options: MatchingOptions,
    ) -> FheBool {
        if let FheResult::Bool(result) = self.find_match(content, pattern, match_options) {
            return result;
        }
        panic!("Unexpected FheResult")
    }

    pub fn find(
        &mut self,
        content: &FheString,
        pattern: &Pattern,
        match_options: MatchingOptions,
    ) -> FheInt16 {
        if let FheResult::Uint(result) = self.find_match(content, pattern, match_options) {
            let shift_count = if let MatchResult::RawStartIndex = match_options.result {
                FheInt16::encrypt_trivial(0)
            } else {
                FheInt16::cast_from(result.gt(1)) * nb_zeros_before(content, result.clone())
            };
            return FheInt16::cast_from(result) - shift_count - 1;
        }
        panic!("Unexpected FheResult");
    }

    fn find_match(
        &mut self,
        content: &FheString,
        pattern: &Pattern,
        match_options: MatchingOptions,
    ) -> FheResult {
        let start = Instant::now();
        if pattern.has_padding() {
            panic!("Padding not supported for the pattern.");
        }
        let full_match = match_options.sof && match_options.eof;
        if content.chars.len() < pattern.len()
            || (!content.has_padding() && full_match && content.chars.len() != pattern.len())
        {
            match match_options.result {
                MatchResult::Bool => FheResult::Bool(FheBool::encrypt_trivial(false)),
                _ => FheResult::Uint(FheUint16::encrypt_trivial(0)),
            };
        }

        let final_op = self.build_execution_plan(content, pattern, match_options);

        let mut remaining_ops: Vec<Execution> =
            self.cache.lock().unwrap().keys().cloned().collect();
        let mut prev_len = remaining_ops.len() + 1;
        info!("Initialized execution plan in {:?}.", start.elapsed());

        while remaining_ops.len() < prev_len {
            prev_len = remaining_ops.len();
            // Idea for further speed improvements: do some branch prediction.
            // For example when the final result look like (a | b) | c
            // compute (a | b), (false | c), (true | c) in the last but one iteration
            // so that we can directly retrieve the final result in the last iteration
            remaining_ops = remaining_ops
                .par_iter()
                .map(|execution| {
                    if self.cache.lock().unwrap().get(execution).unwrap().is_some() {
                        return vec![];
                    }
                    let new_res = match execution {
                        Execution::Eq(c_pos, p_id) => match p_id {
                            PatternId::Zero => Some(FheResult::Bool(content.chars[*c_pos].byte.eq(0))),
                            PatternId::Byte(b) => Some(FheResult::Bool(content.chars[*c_pos].byte.eq(*b))),
                            PatternId::Index(p_pos) => {
                                if let Pattern::Encrypted(p) = pattern {
                                    Some(FheResult::Bool(
                                        content.chars[*c_pos].byte.eq(p.chars[*p_pos].byte.clone())
                                    ))
                                } else {
                                    panic!("Unexpected clear pattern");
                                }
                            }
                        },
                        Execution::And { l_res, r_res } => {
                            let (m_l_res, m_r_res) = {
                                let cache = self.cache.lock().unwrap();
                                match (cache.get(l_res), cache.get(r_res)) {
                                    (Some(l), Some(r)) => (l.clone(), r.clone()),
                                    _ => (None, None),
                                }
                            };

                            match (m_l_res, m_r_res) {
                                (Some(FheResult::Bool(l)), Some(FheResult::Bool(r))) => Some(FheResult::Bool(l & r)),
                                _ => None,
                            }
                        },
                        Execution::Or { l_res, r_res } => {
                            let (m_l_res, m_r_res) = {
                                let cache = self.cache.lock().unwrap();
                                match (cache.get(l_res), cache.get(r_res)) {
                                    (Some(l), Some(r)) => (l.clone(), r.clone()),
                                    _ => (None, None),
                                }
                            };

                            match (m_l_res, m_r_res) {
                                (Some(FheResult::Bool(l)), Some(FheResult::Bool(r))) => Some(FheResult::Bool(l | r)),
                                _ => None,
                            }
                        },
                        Execution::StartIndex { l_res, r_res } => {
                            let (m_l_res, m_r_res) = {
                                let cache = self.cache.lock().unwrap();
                                match (cache.get(l_res), cache.get(r_res)) {
                                    (Some(l), Some(r)) => (l.clone(), r.clone()),
                                    _ => (None, None),
                                }
                            };

                            match (m_l_res, m_r_res) {
                                (Some(FheResult::Uint(l)), Some(FheResult::Uint(r))) => {
                                    let u16_max = FheUint16::encrypt_trivial(u16::MAX);
                                    let new_r = r & (FheUint16::cast_from(!l.gt(0)) * u16_max);
                                    Some(FheResult::Uint(l | new_r))
                                },
                                _ => None,
                            }
                        },
                        Execution::IndexMatch { c_pos, p_pos } => {
                            let pattern_match = Execution::PatternMatch { c_pos: *c_pos, p_pos: *p_pos };
                            let pm_res = self.cache.lock().unwrap().get(&pattern_match).unwrap().clone();

                            if let Some(FheResult::Bool(res)) = pm_res {
                                let must_keep = res & content.chars[*c_pos].byte.gt(0);
                                let u16_max = FheUint16::encrypt_trivial(u16::MAX);
                                Some(FheResult::Uint(
                                    FheUint16::encrypt_trivial((c_pos + 1) as u16) & (FheUint16::cast_from(must_keep) * u16_max)
                                ))
                            } else {
                                None
                            }
                        },
                        Execution::PatternMatch { .. } => None,
                    };

                    if let Some(ref res) = new_res {
                        let _ = self
                            .cache
                            .lock()
                            .unwrap()
                            .get_mut(execution)
                            .unwrap()
                            .insert(res.clone());
                        // If there is a pattern match corresponding to this execution, set its
                        // result
                        if let Some(pm_exec) = self.pm_cache.get(execution) {
                            let _ = self
                                .cache
                                .lock()
                                .unwrap()
                                .get_mut(pm_exec)
                                .unwrap()
                                .insert(res.clone());
                        }
                        return vec![];
                    }
                    vec![execution.clone()]
                })
                .flatten()
                .collect();
        }
        if !remaining_ops.is_empty() {
            panic!(
                "Could not compute {} remaining operations.",
                remaining_ops.len()
            );
        }
        let duration = start.elapsed();
        info!(
            "Completed ~{} FHE operations in {:?}.",
            self.cache.lock().unwrap().len(),
            duration
        );
        self.cache
            .lock()
            .unwrap()
            .get(&final_op)
            .unwrap()
            .clone()
            .unwrap()
    }

    fn build_execution_plan(
        &mut self,
        content: &FheString,
        pattern: &Pattern,
        match_options: MatchingOptions,
    ) -> Execution {
        let max_start = if match_options.sof {
            0
        } else {
            content.chars.len() - pattern.len()
        };
        let op_type = match match_options.result {
            MatchResult::Bool => "or",
            MatchResult::StartIndex | MatchResult::RawStartIndex => "start_index",
        };
        let nodes = self.build_leaves(0, max_start, PatternId::Index(0), op_type);
        let root = self.build_bitwise_execution_tree(nodes, op_type);

        final_op = self.insert_execution_tree(root);
        let mut match_candidates: Vec<(usize, usize)> = (0..=max_start).map(|c_pos| (c_pos, 0)).collect();

        while let Some((c_pos, p_pos)) = match_candidates.pop() {
            let pattern_match = Execution::PatternMatch { c_pos, p_pos };
            let remain_c = content.chars.len() - c_pos;
            let remain_p = pattern.len() - p_pos;

            if self.cache.lock().unwrap().contains_key(&pattern_match) {
                continue;
            }

            let mut maybe_l_res: Option<Execution> = None;
            if remain_p > 0 {
                let p_id = match pattern {
                    Pattern::Clear(ref p) => PatternId::Byte(p.as_bytes()[p_pos]),
                    Pattern::Encrypted(_) => PatternId::Index(p_pos),
                };
                let l_res = self.consume_pattern(
                    (c_pos, remain_c),
                    (p_pos, remain_p),
                    p_id,
                    match_options,
                    content.padding,
                );
                // self.cache.insert(l_res.clone(), None);
                maybe_l_res = Some(l_res);
                if remain_p > 1 {
                    match_candidates.push((c_pos + 1, p_pos + 1));
                }
            }

            let can_consume_zero = remain_c > remain_p
                && ((p_pos == 0 && content.padding.start)
                    || (p_pos > 0 && content.padding.middle)
                    || (remain_p == 0 && content.padding.end));
            let mut maybe_r_res: Option<Execution> = None;
            if can_consume_zero {
                let r_res = self.consume_pattern(
                    (c_pos, remain_c),
                    (p_pos, remain_p),
                    PatternId::Zero,
                    match_options,
                    content.padding,
                );
                // self.cache.insert(r_res.clone(), None);
                maybe_r_res = Some(r_res);
                match_candidates.push((c_pos + 1, p_pos));
            }

            let execution = match (maybe_l_res, maybe_r_res) {
                (Some(l_res), Some(r_res)) => {
                    let ex = Execution::Or {
                        l_res: Box::new(l_res),
                        r_res: Box::new(r_res),
                    };
                    self.cache.lock().unwrap().insert(ex.clone(), None);
                    ex
                }
                (Some(l_res), None) => l_res,
                (None, Some(r_res)) => r_res,
                (None, None) => panic!("Could not build branch at ({c_pos}, {p_pos})."),
            };
            self.pm_cache.insert(execution, pattern_match.clone());
            self.cache.lock().unwrap().insert(pattern_match, None);
        }
        final_op
    }

    fn insert_execution_tree(&mut self, root: ExecutionTree) -> Execution {
        let mut nodes = vec![&root];
        while !nodes.is_empty() {
            nodes = nodes
                .into_iter()
                .flat_map(|node| {
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
                        }
                    };

                    if self.cache.lock().unwrap().contains_key(execution) {
                        return vec![];
                    }
                    self.cache.lock().unwrap().insert(execution.clone(), None);

                    children
                })
                .collect();
        }

        match root {
            ExecutionTree::Node { op, .. } => op,
            ExecutionTree::Leaf(ex) => ex,
        }
    }

    fn build_bitwise_execution_tree(
        &self,
        mut nodes: Vec<ExecutionTree>,
        op_type: &str,
    ) -> ExecutionTree {
        let make_bitwise_op = |l_res: Execution, r_res: Execution| match op_type {
            "and" => Execution::And {
                l_res: Box::new(l_res),
                r_res: Box::new(r_res),
            },
            "or" => Execution::Or {
                l_res: Box::new(l_res),
                r_res: Box::new(r_res),
            },
            "start_index" => Execution::StartIndex {
                l_res: Box::new(l_res),
                r_res: Box::new(r_res),
            },
            s => panic!("Unexpected bitwise operation type '{s}'."),
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
                        (ExecutionTree::Leaf(l_res), ExecutionTree::Leaf(r_res)) => {
                            make_bitwise_op(l_res, r_res)
                        }
                        (
                            ExecutionTree::Node { op: l_res, .. },
                            ExecutionTree::Node { op: r_res, .. },
                        ) => make_bitwise_op(l_res, r_res),
                        _ => panic!("Unexpected Leaf and Node mismatch."),
                    };
                    ExecutionTree::Node {
                        op,
                        left: Box::new(left),
                        right: Box::new(right),
                    }
                })
                .collect();
        }

        nodes.pop().expect("Unexpected empty tree")
    }

    fn build_leaves(
        &mut self,
        c_start: usize,
        c_end: usize,
        p_id: PatternId,
        op_type: &str,
    ) -> Vec<ExecutionTree> {
        let make_leaf_op = |c_pos: usize| match op_type {
            "and" => Execution::Eq(c_pos, p_id),
            "or" => {
                if let PatternId::Index(p_pos) = p_id {
                    Execution::PatternMatch { c_pos, p_pos }
                } else {
                    panic!("Unexpected PatternId");
                }
            },
            "start_index" => {
                if let PatternId::Index(p_pos) = p_id {
                    Execution::IndexMatch { c_pos, p_pos }
                } else {
                    panic!("Unexpected PatternId");
                }

            }
            s => panic!("Unexpected bitwise operation type '{s}'."),
        };

        // Ensure that the left leaves are at even positions to increase cache hits
        let mut nodes: Vec<ExecutionTree> = if (c_end - c_start < 1) || (c_start % 2 > 0) {
            vec![ExecutionTree::Leaf(make_leaf_op(c_start))]
        } else {
            vec![]
        };
        nodes.extend((c_start..=c_end).map(|i| ExecutionTree::Leaf(make_leaf_op(i))));

        nodes
    }

    // A function that inserts all necessary executions to get the result of a pattern match
    // starting at (c_pos, p_pos) The p_id parameter can be Zero or a Byte if we consume the
    // content character at c_pos as a Zero or the pattern byte at p_pos. It returns the root
    // Execution.
    fn consume_pattern(
        &mut self,
        c_range: (usize, usize),
        p_range: (usize, usize),
        p_id: PatternId,
        match_options: MatchingOptions,
        padding: PaddingOptions,
    ) -> Execution {
        let (c_pos, remain_c) = c_range;
        let (p_pos, remain_p) = p_range;
        let zero_prefixed = c_pos > 0 && p_pos == 0 && match_options.sof && padding.start;
        let zero_suffixed = remain_c > 1 && remain_p == 1 && match_options.eof && padding.end;

        let p_eq = Execution::Eq(c_pos, p_id);
        self.cache.lock().unwrap().insert(p_eq.clone(), None);

        let main_match = if remain_p < 2 {
            // This is the last char of the pattern to match
            p_eq
        } else {
            let pattern_match = match p_id {
                PatternId::Zero => Execution::PatternMatch {
                    c_pos: c_pos + 1,
                    p_pos,
                },
                _ => Execution::PatternMatch {
                    c_pos: c_pos + 1,
                    p_pos: p_pos + 1,
                },
            };
            let ex_and = Execution::And {
                l_res: Box::new(p_eq),
                r_res: Box::new(pattern_match),
            };
            self.cache.lock().unwrap().insert(ex_and.clone(), None);
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
                let ex_and = Execution::And {
                    l_res: Box::new(zero_prefix_ex),
                    r_res: Box::new(main_match),
                };
                self.cache.lock().unwrap().insert(ex_and.clone(), None);
                ex_and
            }
            (false, true) => {
                let zero_suffix_ex = insert_zero_range(c_pos + 1, c_pos + remain_c - 1);
                let ex_and = Execution::And {
                    l_res: Box::new(main_match),
                    r_res: Box::new(zero_suffix_ex),
                };
                self.cache.lock().unwrap().insert(ex_and.clone(), None);
                ex_and
            }
            (true, true) => {
                let zero_prefix_ex = insert_zero_range(0, c_pos - 1);
                let zero_suffix_ex = insert_zero_range(c_pos + 1, c_pos + remain_c - 1);
                let ex_and = Execution::And {
                    l_res: Box::new(zero_prefix_ex),
                    r_res: Box::new(main_match),
                };
                self.cache.lock().unwrap().insert(ex_and.clone(), None);

                let final_and = Execution::And {
                    l_res: Box::new(ex_and),
                    r_res: Box::new(zero_suffix_ex),
                };
                self.cache.lock().unwrap().insert(final_and.clone(), None);
                final_and
            }
        }
    }
}

fn nb_zeros_before(content: &FheString, index: FheUint16) -> FheInt16 {
    let mut res = FheUint16::encrypt_trivial(0);
    content.chars.iter()
        .enumerate()
        .for_each(|(i, c)| {
            let must_count = c.byte.eq(0) & index.gt(i as u16);
            res = res.clone() + FheUint16::cast_from(must_count);
        });

    FheInt16::cast_from(res)
}