use rstd::prelude::*;

// Encoding library
use parity_codec::Encode;

// Enables access to the runtime storage
use srml_support::{StorageValue, dispatch::Result};

// Enables us to do hashing
use runtime_primitives::traits::Hash;

// Enables access to account balances
use {balances, system::{self, ensure_signed}};


pub trait Trait: balances::Trait + system::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}


decl_module! {
  pub struct Module<T: Trait> for enum Call where origin: T::Origin {
    fn deposit_event() = default;

    // creates new multi-signature wallet
    fn create(origin, owners: Vec<T::AccountId>, signatures_required: u64) -> Result {
        Ok(())
    }

    // requests withdrawal from a wallet
    // actual withdrawal will be made when there are enough signatures
    fn withdraw(origin, wallet: T::AccountId, to: T::AccountId, value: T::Balance) -> Result {
        Ok(())
    }

    // deposits are made using balances.transfer(to_wallet: T::AccountId, value: T::Balance)
  }
}


decl_storage! {
	trait Store for Module<T: Trait> as Multisig {
	}
}


decl_event!(
	pub enum Event<T> where AccountId = <T as system::Trait>::AccountId {
		/// Created new wallet identified by Runtime::AccountId type.
		Created(AccountId),
	}
);
