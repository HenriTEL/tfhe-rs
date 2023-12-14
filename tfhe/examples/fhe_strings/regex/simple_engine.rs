use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use log::info;
use rayon::prelude::*;

use tfhe::prelude::*;
use tfhe::FheBool;

use crate::ciphertext::{FheString, PaddingOptions};


#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum PatternId {
    Zero,
    Index(usize),
    Byte(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum BitwiseParam {
    EqRes(usize, PatternId),
    AndRes { l_res: Box<BitwiseParam>, r_res:  Box<BitwiseParam> },
    OrRes { l_res: Box<BitwiseParam>, r_res:  Box<BitwiseParam> },
    PatternMatchRes { c_pos: usize, p_pos: usize },
}


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum BitwiseExecId {
    And { l_res: BitwiseParam, r_res:  BitwiseParam },
    Or { l_res: BitwiseParam, r_res:  BitwiseParam},
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ExecutionId {
    BitwiseOp(BitwiseExecId),
    PatternMatch { c_pos: usize, p_pos: usize },
    // TODO PlaceHolder,
}

#[derive(Debug, Clone)]
enum BitwiseTree {
    Leaf(BitwiseParam),
    Node {
        op: BitwiseExecId,
        left: Box<BitwiseTree>,
        right: Box<BitwiseTree>,
    },
}

pub struct SimpleEngine {
    cache: Arc<Mutex< HashMap<ExecutionId, (Option<FheBool>, usize)> >>,
    pm_ops: Arc<Mutex< HashMap<ExecutionId, BitwiseParam> >>,
    bitwise_ops: Arc<Mutex< Vec<HashSet<BitwiseExecId>> >>,
    eq_ops: HashMap<(usize, PatternId), Option<FheBool>>,

    ops_count: usize,
    cache_hits: usize,
}

impl SimpleEngine {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            pm_ops: Arc::new(Mutex::new(HashMap::new())),
            bitwise_ops: Arc::new(Mutex::new(vec![])),
            eq_ops: HashMap::new(),

            ops_count: 0,
            cache_hits: 0,
        }
    }

    pub fn has_match(&mut self, content: &FheString, pattern: &String, match_options: MatchingOptions) -> FheBool {
        let has_padding = content.padding.start | content.padding.middle | content.padding.end;
        let full_match =  match_options.sof && match_options.eof;
        if content.chars.len() < pattern.len() || (!has_padding && full_match && content.chars.len() != pattern.len()) {
            return FheBool::encrypt_trivial(false);
        }

        self.build_execution_plan(content, pattern, match_options);
        info!("Built pattern matching execution plan.");

        self.eq_ops.iter_mut()
            .for_each(|((c_pos, p_id),  res)| {
                let _ = res.insert(content.chars[*c_pos].byte.eq(match p_id {
                    PatternId::Zero => 0_u8,
                    PatternId::Byte(b) => *b,
                    PatternId::Index(..) => panic!("Unexpected encrypted pattern Id."),
                }));
            });
        info!("Performed {} FHE equality checks.", self.eq_ops.len());

        let get_result = |bw_param: &BitwiseParam| -> Option<FheBool> {
            match bw_param {
                BitwiseParam::AndRes { l_res, r_res } => {
                    let bw_ex_id = BitwiseExecId::And { l_res: *l_res.clone(), r_res: *r_res.clone() };
                    match self.cache.lock().unwrap().get(&ExecutionId::BitwiseOp(bw_ex_id)) {
                        Some((result, _)) => result.clone(),
                        None => panic!("And res not found in cache"),
                    }
                },
                BitwiseParam::OrRes { l_res, r_res } => {
                    let bw_ex_id = BitwiseExecId::Or { l_res: *l_res.clone(), r_res: *r_res.clone() };
                    self.cache.lock().unwrap().get(&ExecutionId::BitwiseOp(bw_ex_id)).unwrap().clone().0
                },
                BitwiseParam::EqRes(c_pos, p_id) => {
                    self.eq_ops.get(&(*c_pos, *p_id)).unwrap().clone()
                },
                BitwiseParam::PatternMatchRes { c_pos, p_pos } => {
                    let ex_id = ExecutionId::PatternMatch { c_pos: *c_pos, p_pos: *p_pos };
                    
                    let bw_param = self.pm_ops.lock().unwrap().get(&ex_id).unwrap().clone();
                    match bw_param {
                        BitwiseParam::EqRes(c_pos, p_id) => self.eq_ops.get(&(c_pos, p_id)).unwrap().clone(),
                        BitwiseParam::AndRes { l_res, r_res } => {
                            let bw_ex_id = BitwiseExecId::And { l_res: *l_res.clone(), r_res: *r_res.clone() };
                            self.cache.lock().unwrap().get(&ExecutionId::BitwiseOp(bw_ex_id)).unwrap().0.clone()
                        },
                        BitwiseParam::OrRes { l_res, r_res } => {
                            let bw_ex_id = BitwiseExecId::Or { l_res: *l_res.clone(), r_res: *r_res.clone() };
                            self.cache.lock().unwrap().get(&ExecutionId::BitwiseOp(bw_ex_id)).unwrap().clone().0
                        },
                        BitwiseParam::PatternMatchRes { .. } => panic!("Unexpected PatternMatchRes"),
                    }
                }
            }
        };

        let mut skipped_ops = vec![];
        for ops_vec in self.bitwise_ops.lock().unwrap().iter().rev() {
            skipped_ops = ops_vec.iter().chain(skipped_ops.iter())
                .map( |bw_ex_id| {
                    let ex_id = ExecutionId::BitwiseOp(bw_ex_id.clone());
                    if let Some((Some(_), _)) = self.cache.lock().unwrap().get(&ex_id) {
                        return vec![];
                    }
                    
                    let result = match bw_ex_id {
                        BitwiseExecId::And { l_res, r_res } => {
                            match (get_result(l_res), get_result(r_res)) {
                                (Some(a), Some(b)) => Some(a & b),
                                _ => None,
                            }
                        },
                        BitwiseExecId::Or { l_res, r_res } => {
                            match (get_result(l_res), get_result(r_res)) {
                                (Some(a), Some(b)) => Some(a | b),
                                _ => None,
                            }
                        },
                    };
                    if let Some(res) = result {
                        let _ = self.cache.lock().unwrap().get_mut(&ex_id).unwrap().0.insert(res);
                        return vec![];
                    } else {
                        return vec![bw_ex_id.clone()];
                    }
                    
                })
                .flatten()
                .collect();
        };
        let mut prev_len = 1000;
        while prev_len > skipped_ops.len() {
            prev_len = skipped_ops.len();
            info!("Remaining ops: {prev_len}");
            skipped_ops = skipped_ops.iter()
                .map( |bw_ex_id| {
                    let ex_id = ExecutionId::BitwiseOp(bw_ex_id.clone());
                    if let Some((Some(_), _)) = self.cache.lock().unwrap().get(&ex_id) {
                        return vec![];
                    }
                    let result = match bw_ex_id {
                        BitwiseExecId::And { l_res, r_res } => {
                            match (get_result(l_res), get_result(r_res)) {
                                (Some(a), Some(b)) => Some(a & b),
                                _ => None,
                            }
                        },
                        BitwiseExecId::Or { l_res, r_res } => {
                            match (get_result(l_res), get_result(r_res)) {
                                (Some(a), Some(b)) => Some(a | b),
                                _ => None,
                            }
                        },
                    };
                    if let Some(res) = result {
                        let _ = self.cache.lock().unwrap().get_mut(&ex_id).unwrap().0.insert(res);
                        return vec![];
                    } else {
                        return vec![bw_ex_id.clone()];
                    }
                    
                })
                .flatten()
                .collect();
        }

        if skipped_ops.len() > 0 {
            info!("remain:\n {:?}", skipped_ops);
            panic!("skipped_ops not empty");
        }
        let root_ex_id = ExecutionId::BitwiseOp(self.bitwise_ops.lock().unwrap()[0].clone().into_iter().next().unwrap());

        self.cache.lock().unwrap().get(&root_ex_id).unwrap().clone().0.unwrap()
    }

    fn build_execution_plan(&mut self, content: &FheString, pattern: &String, match_options: MatchingOptions) {
        let mut init_remain = vec![];
        if match_options.sof {
            init_remain.push((0, 0, 0));
        } else {
            let max_start = content.chars.len() - pattern.len();
            if max_start > 0 {
                self.insert_bitwise_tree(0, max_start, PatternId::Index(0), "or", 0);
            }
            let depth = self.bitwise_ops.lock().unwrap().len();
            init_remain.push((0, 0, depth));
        }
        let mut remain: VecDeque<(usize, usize, usize)> = init_remain.into_iter().collect();

        while remain.len() > 0 {
            let (c_pos, p_pos, depth) = remain.pop_front().unwrap();
            let current_match_id = ExecutionId::PatternMatch { c_pos, p_pos };
            let remain_c = content.chars.len() - c_pos;
            let remain_p = pattern.len() - p_pos;

            if self.pm_ops.lock().unwrap().contains_key(&current_match_id) {
                continue
            }

            let mut maybe_l_res: Option<BitwiseParam> = None;
            let mut consume_zero_depth = depth;
            if remain_p > 0 {
                let p_id = PatternId::Byte(pattern.as_bytes()[p_pos]);
                let _ = maybe_l_res.insert(
                    self.consume_pattern(c_pos, p_pos, depth, p_id, remain_c, remain_p, match_options, content.padding)
                );
                consume_zero_depth += 1;
                // TODO remove
                if remain_p > 1 {
                    remain.push_back((c_pos + 1, p_pos + 1, depth + 1));
                }
            }
        
            // TODO remove (remain_p == 0 && content.padding.end) as it's dealt by the zero_suffix constraint
            let can_consume_zero = remain_c - 1 >= remain_p
                && ((p_pos == 0 && content.padding.start) || (p_pos > 0 && content.padding.middle) || (remain_p == 0 && content.padding.end));
            let mut maybe_r_res: Option<BitwiseParam> = None;
            if can_consume_zero {
                let _ = maybe_r_res.insert(
                    self.consume_pattern(c_pos, p_pos, consume_zero_depth, PatternId::Zero, remain_c, remain_p, match_options, content.padding)
                );
                // TODO remove
                remain.push_back((c_pos + 1, p_pos, depth + 1));
            }

            match (maybe_l_res, maybe_r_res) {
                (Some(l_res), Some(r_res)) => {
                    self.insert_bitwise_param(l_res.clone(), depth + 1);
                    self.insert_bitwise_param(r_res.clone(), depth + 1);
                    let bw_param = BitwiseParam::OrRes { l_res: Box::new(l_res), r_res: Box::new(r_res) };
                    self.insert_bitwise_param(bw_param.clone(), depth);
                    self.pm_ops.lock().unwrap().insert(current_match_id, bw_param);
                },
                (Some(l_res), None) => {
                    self.insert_bitwise_param(l_res.clone(), depth);
                    self.pm_ops.lock().unwrap().insert(current_match_id, l_res);
                },
                (None, Some(r_res)) => {
                    self.insert_bitwise_param(r_res.clone(), depth);
                    self.pm_ops.lock().unwrap().insert(current_match_id, r_res);
                },
                (None, None) => panic!("Could not build branch at ({c_pos}, {p_pos})."),
            };
        }
    }

    fn insert_bitwise_tree(&mut self, c_start: usize, c_end: usize, p_id: PatternId, op_type: &str, mut depth: usize) -> BitwiseParam {
        let root = self.build_bitwise_tree(c_start, c_end, p_id, op_type);
        let mut nodes = vec![&root];

        while !nodes.is_empty() {
            nodes = nodes.iter().map(|node| {
                let mut children: Vec<&BitwiseTree> = vec![];
                let bw = match node {
                    BitwiseTree::Leaf(bw_param) => bw_param.clone(),
                    // match bw_param {
                    //     BitwiseParam::AndRes { l_res, r_res } => BitwiseExecId::And { l_res: *l_res.clone(), r_res: *r_res.clone() },
                    //     BitwiseParam::OrRes { l_res, r_res } => BitwiseExecId::Or { l_res: *l_res.clone(), r_res: *r_res.clone() },
                    //     BitwiseParam::EqRes(..) => panic!("Unexpected BitwiseParam::EqRes"),
                    //     BitwiseParam::PatternMatchRes { .. } => panic!("Unexpected BitwiseParam::PatternMatchRes"),
                    // },
                    BitwiseTree::Node { op, left, right } => {
                        if let (BitwiseTree::Node{..}, BitwiseTree::Node{..}) = (&**left, &**right) {
                            children.push(left);
                            children.push(right);
                        }
                        match op {
                            BitwiseExecId::And { l_res, r_res } => BitwiseParam::AndRes { l_res: Box::new(l_res.clone()), r_res: Box::new(r_res.clone()) },
                            BitwiseExecId::Or { l_res, r_res } => BitwiseParam::OrRes { l_res: Box::new(l_res.clone()), r_res: Box::new(r_res.clone()) },
                        }
                    },
                };
                if self.insert_bitwise_param(bw, depth) {
                    return children;
                }

                vec![]
            })
            .flatten()
            .collect();
            depth += 1;
        }

        match root {
            BitwiseTree::Node { op, .. } => match op {
                BitwiseExecId::And { l_res, r_res } => BitwiseParam::AndRes { l_res: Box::new(l_res), r_res: Box::new(r_res) },
                BitwiseExecId::Or { l_res, r_res } => BitwiseParam::OrRes { l_res: Box::new(l_res), r_res: Box::new(r_res) },
            },
            BitwiseTree::Leaf(bw_param) => bw_param.clone(),
        }
    }

    // A 2D vec iversed tree where the first layer consists of equality checks between content characters
    // ranging from c_start until c_end and a pattern p_id.
    // The layer at i+1 rduce the results at layer i by pairing its element in the bitwise operation specified by op_type.
    // Until we end with the last remaining bitwise operation at the bottom layer.
    fn build_bitwise_tree(&mut self, c_start: usize, c_end: usize, p_id: PatternId, op_type: &str) -> BitwiseTree {
        let mut make_leaf_op = |c_pos: usize| {
            match op_type {
                "and" => {
                    self.eq_ops.insert((c_pos, p_id), None);
                    BitwiseParam::EqRes(c_pos, p_id)
                },
                "or" => {
                    match p_id {
                        PatternId::Index(p_pos) => BitwiseParam::PatternMatchRes { c_pos, p_pos },
                        _ => panic!("Unexpected PatternId"),
                    }
                },
                s => panic!("Unexpected bitwise operation type '{s}'.")
            }
        };

        if c_end - c_start < 1  {
            return BitwiseTree::Leaf(make_leaf_op(c_start))
        }
        // Make sure that the left nodes are even increase cache hits
        let mut nodes: Vec<BitwiseTree> = if c_start % 2 > 0 {
            vec![BitwiseTree::Leaf(make_leaf_op(c_start))]
        } else {
            vec![]
        };

        nodes.extend((c_start..=c_end).map(|i| BitwiseTree::Leaf(make_leaf_op(i))));
        if nodes.len() % 2 > 0 {
            nodes.push(BitwiseTree::Leaf(make_leaf_op(c_end)));
        }

        let make_bw_op = |l_res, r_res| {
            match op_type {
                "and" => BitwiseExecId::And { l_res, r_res },
                "or" => BitwiseExecId::Or { l_res, r_res },
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
                        (BitwiseTree::Leaf(l_res), BitwiseTree::Leaf(r_res)) => make_bw_op(l_res, r_res),
                        (BitwiseTree::Node { op: l_id, .. }, BitwiseTree::Node { op: r_id, .. }) => {
                            let l_res = match l_id {
                                // TODO remove those converation operations by implementing the proper into() traits
                                BitwiseExecId::And { l_res, r_res } => BitwiseParam::AndRes { l_res: Box::new(l_res), r_res: Box::new(r_res) },
                                BitwiseExecId::Or { l_res, r_res } => BitwiseParam::OrRes { l_res: Box::new(l_res), r_res: Box::new(r_res) },
                            };
                            let r_res = match r_id {
                                BitwiseExecId::And { l_res, r_res } => BitwiseParam::AndRes { l_res: Box::new(l_res), r_res: Box::new(r_res) },
                                BitwiseExecId::Or { l_res, r_res } => BitwiseParam::OrRes { l_res: Box::new(l_res), r_res: Box::new(r_res) },
                            };
                            make_bw_op(l_res, r_res)
                        },
                        _ => panic!("Unexpected Leaf and Node mismatch.")
                    };
                    BitwiseTree::Node { op, left: Box::new(left), right: Box::new(right) }
                })
                .collect();
        }


        nodes.pop().expect("Unexpected empty tree")
    }

    fn consume_pattern(&mut self, c_pos: usize, p_pos: usize, depth: usize, p_id: PatternId, remain_c: usize, remain_p: usize, match_options: MatchingOptions, padding: PaddingOptions) -> BitwiseParam {
        let zero_prefixed = c_pos > 0 && p_pos == 0 && match_options.sof && padding.start;
        let zero_suffixed = remain_c > 1 && remain_p == 1 && match_options.eof && padding.end;

        self.eq_ops.insert((c_pos, p_id), None);
        let main_match = if remain_p < 2 {
            BitwiseParam::EqRes(c_pos, p_id)
        } else {
            let pm = match p_id {
                PatternId::Zero => BitwiseParam::PatternMatchRes { c_pos: c_pos + 1, p_pos },
                _ => BitwiseParam::PatternMatchRes { c_pos: c_pos + 1, p_pos: p_pos + 1 },
            };

            BitwiseParam::AndRes {
                l_res: Box::new(BitwiseParam::EqRes(c_pos, p_id)),
                r_res: Box::new(pm)
            }
        };

        match (zero_prefixed, zero_suffixed) {
            (false, false) => main_match,
            (true, false) => {
                let zero_prefix = self.insert_bitwise_tree(0, c_pos - 1, PatternId::Zero, "and", depth + 1);
                self.insert_bitwise_param(main_match.clone(), depth + 1);

                BitwiseParam::AndRes { l_res: Box::new(zero_prefix), r_res: Box::new(main_match) }
            },
            (false, true) => {
                let zero_suffix = self.insert_bitwise_tree(c_pos + 1,  c_pos + remain_c - 1, PatternId::Zero, "and", depth + 1);
                self.insert_bitwise_param(main_match.clone(), depth + 1);

                BitwiseParam::AndRes { l_res: Box::new(main_match), r_res: Box::new(zero_suffix) }
            },
            (true, true) => {
                let zero_prefix = self.insert_bitwise_tree(0, c_pos - 1, PatternId::Zero, "and", depth + 2);
                self.insert_bitwise_param(main_match.clone(), depth + 2);

                let ex_res = BitwiseParam::AndRes { l_res: Box::new(zero_prefix), r_res: Box::new(main_match) };
                self.insert_bitwise_param(ex_res.clone(), depth + 1);
                let zero_suffix = self.insert_bitwise_tree(c_pos + 1,  c_pos + remain_c - 1, PatternId::Zero, "and", depth + 1);

                BitwiseParam::AndRes { l_res: Box::new(ex_res), r_res: Box::new(zero_suffix)  }
            }
        }
    }

    fn insert_bitwise_op(&mut self, bw_ex_id: BitwiseExecId, mut depth: usize) -> bool {
        let ex_id: ExecutionId = ExecutionId::BitwiseOp(bw_ex_id.clone());
        let mut maybe_old_depth = None;

        {
            let mut cache = self.cache.lock().unwrap();
            if let Some((_, cache_depth)) = cache.get_mut(&ex_id) {
                if cache_depth >= &mut depth  {
                    return false;
                }
                maybe_old_depth = Some(cache_depth.clone());
                *cache_depth = depth;
            } else {
                cache.insert(ex_id, (None, depth));
            }
        }
        
        {
            let mut bitwise_ops = self.bitwise_ops.lock().unwrap();
            if let Some(old_depth) = maybe_old_depth {
                bitwise_ops[old_depth].remove(&bw_ex_id);
            }
            while depth >= bitwise_ops.len() {
                bitwise_ops.push(HashSet::new());
            }
            bitwise_ops[depth].insert(bw_ex_id);
        }

        true
    }

    fn insert_bitwise_param(&mut self, bw_param: BitwiseParam, depth: usize) -> bool {
        match bw_param {
            BitwiseParam::AndRes { l_res, r_res } => {
                let bw_exec_id = BitwiseExecId::And { l_res: *l_res, r_res: *r_res };
                self.insert_bitwise_op(bw_exec_id, depth)
            },
            BitwiseParam::OrRes { l_res, r_res } => {
                let bw_exec_id = BitwiseExecId::Or { l_res: *l_res, r_res: *r_res };
                self.insert_bitwise_op(bw_exec_id, depth)
            },
            BitwiseParam::EqRes(c_pos, _) => false,
            BitwiseParam::PatternMatchRes{ c_pos, .. } => false,
        }
    }
}


#[derive(Default, Debug, Copy, Clone)]
pub struct MatchingOptions {
    pub sof: bool,
    pub eof: bool,
}