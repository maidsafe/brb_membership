// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! BRB Dynamic Membership enables nodes to dynamically join and leave a BRB voting group.
//!
//! For an overview, see:
//! https://github.com/maidsafe/brb/blob/master/doc/BRB.pdf?raw=true

#![deny(missing_docs)]

pub mod brb_membership;
pub use crate::brb_membership::{Ballot, Generation, Reconfig, State, Vote, VoteMsg};

pub mod error;
pub use crate::error::Error;

pub mod actor;
pub use actor::{Actor, Sig, SigningActor};

pub use signature;
