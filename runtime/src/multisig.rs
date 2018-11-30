use rstd::prelude::*;

// Encoding library
use parity_codec::{Encode, Decode, HasCompact};

// Enables access to the runtime storage
use srml_support::{StorageMap, StorageValue, dispatch::Result};

//use srml_support::{StorageValue, StorageMap, Parameter, Dispatchable, IsSubType};

// Enables us to do hashing
use runtime_primitives::traits::Hash;

// Enables access to account balances
use {balances, system::{self, ensure_signed}};


pub trait Trait: balances::Trait + system::Trait {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}



// TODO special type for multisig id
decl_module! {
  pub struct Module<T: Trait> for enum Call where origin: T::Origin {
    fn deposit_event() = default;

    // creates new multi-signature wallet
    fn create(origin, owners: Vec<balances::Address<T>>, signatures_required: <u64 as HasCompact>::Type) -> Result {
        let sender = ensure_signed(origin)?;

        let owners = owners.iter().map(|owner| <balances::Module<T>>::lookup(owner.clone()).unwrap()).collect::<Vec<_>>();
        let signatures_required: u64 = signatures_required.into();

        if 0 == owners.len() || owners.len() > 64 {
            return Err("invalid number of owners");
        }
        if 0 == signatures_required || signatures_required > owners.len() as u64 {
            return Err("invalid number of signatures");
        }

        let this_nonce: u64 = Self::global_nonce();
        <GlobalNonce<T>>::mutate(|nonce| *nonce += 1);

        let mut buf = Vec::new();
        buf.extend_from_slice(&sender.encode());
        buf.extend_from_slice(&this_nonce.encode());
        let h: T::Hash = T::Hashing::hash(&buf[..]);

		let wallet_id = T::AccountId::decode(&mut &h.encode()[..]).unwrap();

        <Owners<T>>::insert(&wallet_id, owners);
        <Signatures<T>>::insert(&wallet_id, signatures_required);

        Self::deposit_event(RawEvent::Created(wallet_id));

        Ok(())
    }

    // requests withdrawal from a wallet
    // actual withdrawal will be made when there are enough signatures
    fn withdraw(origin, wallet: balances::Address<T>, to: balances::Address<T>, value: <T::Balance as HasCompact>::Type) -> Result {
        let who = ensure_signed(origin)?;
        let wallet = <balances::Module<T>>::lookup(wallet)?;
        let to = <balances::Module<T>>::lookup(to)?;
        let value = value.into();

        ensure!(<Owners<T>>::exists(wallet.clone()), "wallet doesn't exists");

		let owners = <Owners<T>>::get(wallet.clone());
        ensure!(owners.iter().any(|owner| *owner == who), "sender isn't owner");

    	let index = owners.iter().position(|owner| *owner == who).unwrap();

		let mut buf = Vec::new();
		buf.append(&mut wallet.encode());
		buf.append(&mut to.encode());
		buf.append(&mut value.encode());

        let operation_hash = T::Hashing::hash(&buf[..]);

        let bitmask: u64;

		if !<OperationBitmask<T>>::exists(operation_hash) {
			<OperationBitmask<T>>::insert(operation_hash, 1 << index);
			bitmask = 1 << index;
		}
		else {
			bitmask = <OperationBitmask<T>>::get(operation_hash);
			ensure!((bitmask & (1 << index)) == 0, "sender already signed");
			<OperationBitmask<T>>::mutate(operation_hash, |bitmask| *bitmask |= 1 << index);
		}

		if Self::signs_count(&bitmask) == <Signatures<T>>::get(&wallet) {
			<OperationBitmask<T>>::remove(operation_hash);
			Self::deposit_event(RawEvent::Withdraw(wallet.clone(), to.clone(), value));
			return <balances::Module<T>>::transfer_without_sign(wallet, balances::address::Address::Id(to), value);
		}

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
	add_extra_genesis {
		config(_marker): ::std::marker::PhantomData<T>;
		build(|_, _, _| {});
	}
}


decl_event!(
	pub enum Event<T> where
	    AccountId = <T as system::Trait>::AccountId,
		Balance = <T as balances::Trait>::Balance
	{
		/// Created new wallet identified by Runtime::AccountId type.
		Created(AccountId),
		Withdraw(AccountId, AccountId, Balance),
	}
);


impl<T: Trait> Module<T> {
    // PUBLIC IMMUTABLES

    /// The combined balance of `who`.
    pub fn signs_count(bitmask: &u64) -> u64 {
        let mut count = 0;
        let mut mask = *bitmask;
        while mask > 0 {
            if mask & 1 == 1 {
                count += 1;
            }
            mask >>= 1;
        }

        return count;
    }
}