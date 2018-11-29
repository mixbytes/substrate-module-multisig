use rstd::prelude::*;

// Encoding library
use parity_codec::{Encode, Decode};

// Enables access to the runtime storage
use srml_support::{StorageValue, dispatch::Result};

// Enables us to do hashing
use runtime_primitives::traits::Hash;

// Enables access to account balances
use {balances, system::{self, ensure_signed}};

use primitives::convert_hash;

use rstd::marker::PhantomData;


pub trait Trait: balances::Trait + system::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}



// TODO special type for multisig id

decl_module! {
  pub struct Module<T: Trait> for enum Call where origin: T::Origin {
    fn deposit_event() = default;

    // creates new multi-signature wallet
    fn create(origin, owners: Vec<T::AccountId>, signatures_required: u64) -> Result {
        let sender = ensure_signed(origin)?;

        if 0 == owners.len() || owners.len() > 64 {
            return Err("invalid number of owners");
        }
        if signatures_required > owners.len() as u64 {
            return Err("invalid number of signatures");
        }

        let this_nonce: u64 = Self::global_nonce();
        <GlobalNonce<T>>::mutate(|nonce| *nonce += 1);

        let mut buf = Vec::new();
        buf.extend_from_slice(&sender.encode());
        buf.extend_from_slice(&nonce.encode());
        let h: T::Hash = T::Hashing::hash(&buf[..]);

        let walletId: T::AccountId = convert_hash(&h);
//        <Owners<T>>::

        Ok(())
    }

    // requests withdrawal from a wallet
    // actual withdrawal will be made when there are enough signatures
    fn withdraw(origin, wallet: T::AccountId, to: T::AccountId, value: T::Balance) -> Result {
        let sender = ensure_signed(origin)?;

        Ok(())
    }

    // deposits are made using balances.transfer(to_wallet: T::AccountId, value: T::Balance)
  }
}


decl_storage! {
	trait Store for Module<T: Trait> as Multisig {
	    // Total number of multisig wallets
	    pub GlobalNonce get(global_nonce): u64;

	    // List of owners for each multisig
		pub Owners get(owners): map T::AccountId => Vec<T::AccountId>;

		// Signatures quorum for each multisig
		pub Signatures get(signatures_required): map T::AccountId => u64;

		// Bitmask of signatures for operations
		// Operation is Hash(operation_name, wallet id, operation parameters)
		pub OperationBitmask get(operation_bitmask): map T::Hash => u64;
	}
}


decl_event!(
	pub enum Event<T> where AccountId = <T as system::Trait>::AccountId {
		/// Created new wallet identified by Runtime::AccountId type.
		Created(AccountId),
	}
);
