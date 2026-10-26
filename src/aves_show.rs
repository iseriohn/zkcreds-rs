//! AVES presentations: one credential use per poll, bound to a public response.
//!
//! The credential seed must be included in the attributes committed at issuance. A verifier
//! must also verify the zkcreds issuance/membership linkage proof, reject a token already seen
//! for the poll, and compare `payload` with the response in the AVES index proof. In particular,
//! a value commitment is public here, while its opening and value stay outside this circuit.

use crate::{
    attrs::{AccountableAttrs, AccountableAttrsVar},
    pred::PredicateChecker,
};

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    Error as ArkError,
};
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use ark_serialize::SerializationError;
use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon, PoseidonParameters};
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget, PoseidonParametersVar};

// Distinct from the domain separators in the existing show gadgets (123, 124, and 125).
const TOKEN_DOMAIN: u64 = 0x4156_4553_01;
const PAYLOAD_DOMAIN: u64 = 0x4156_4553_02;
const TAG_DOMAIN: u64 = 0x4156_4553_03;

/// The response visible to the AVES sampler. Commitment bytes must be the canonical,
/// compressed 32-byte encoding of the same Ristretto point used in the AVES index proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvesPayload {
    /// Multi-choice count: the choice is public.
    Choice(u64),
    /// SUM/AVG/RANK: the value is private and this commitment is public.
    ValueCommitment([u8; 32]),
}

impl AvesPayload {
    /// Encode the payload injectively as a kind and two 128-bit field limbs. Splitting the
    /// commitment avoids reducing a 256-bit compressed point modulo the SNARK field.
    pub fn to_field_elements<F: PrimeField>(&self) -> [F; 3] {
        match self {
            Self::Choice(choice) => [F::from(1u8), F::from(*choice), F::from(0u8)],
            Self::ValueCommitment(bytes) => [
                F::from(2u8),
                F::from_le_bytes_mod_order(&bytes[..16]),
                F::from_le_bytes_mod_order(&bytes[16..]),
            ],
        }
    }
}

/// Public statement proved by an AVES credential presentation.
#[derive(Clone)]
pub struct AvesPresentation<F: PrimeField> {
    pub poll_id: F,
    pub payload: AvesPayload,
    /// Deterministic per credential and poll; the verifier must accept it only once.
    pub token: F,
    /// Binds this credential presentation to the public response payload.
    pub tag: F,
}

impl<F: PrimeField> AvesPresentation<F> {
    /// Canonical token bytes to use as the AVES entry ID and duplicate-detection key.
    pub fn entry_id(&self) -> Result<Vec<u8>, SerializationError> {
        let mut bytes = Vec::new();
        self.token.serialize(&mut bytes)?;
        Ok(bytes)
    }

    /// Compute the native public outputs from a credential whose seed is committed at issuance.
    pub fn from_attrs<A, AC>(
        attrs: &A,
        params: PoseidonParameters<F>,
        poll_id: F,
        payload: AvesPayload,
    ) -> Result<Self, ArkError>
    where
        A: AccountableAttrs<F, AC, Seed = F>,
        AC: CommitmentScheme,
        AC::Output: ToConstraintField<F>,
    {
        let h = Poseidon::new(params);
        let seed = attrs.get_seed();
        let [kind, lo, hi] = payload.to_field_elements::<F>();
        let token = h.hash(&[F::from(TOKEN_DOMAIN), poll_id, seed])?;
        let payload_hash = h.hash(&[F::from(PAYLOAD_DOMAIN), kind, lo, hi])?;
        let tag = h.hash(&[F::from(TAG_DOMAIN), poll_id, seed, payload_hash])?;
        Ok(Self {
            poll_id,
            payload,
            token,
            tag,
        })
    }
}

/// Predicate for a linked zkcreds presentation. The same CRS works for every poll and
/// both payload kinds because the circuit shape does not depend on the payload.
#[derive(Clone)]
pub struct AvesShowChecker<F: PrimeField> {
    pub presentation: AvesPresentation<F>,
    pub params: PoseidonParameters<F>,
}

impl<F, A, AV, AC, ACG> PredicateChecker<F, A, AV, AC, ACG> for AvesShowChecker<F>
where
    F: PrimeField,
    A: AccountableAttrs<F, AC, Seed = F>,
    AV: AccountableAttrsVar<F, A, AC, ACG, Seed = FpVar<F>>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, F>,
    AC::Output: ToConstraintField<F>,
{
    fn pred(self, cs: ConstraintSystemRef<F>, attrs: &AV) -> Result<(), SynthesisError> {
        let params =
            PoseidonParametersVar::new_constant(ns!(cs, "AVES Poseidon params"), &self.params)?;
        let h = PoseidonGadget { params };
        let [kind, lo, hi] = self.presentation.payload.to_field_elements::<F>();

        let poll_id = FpVar::new_input(ns!(cs, "poll ID"), || Ok(self.presentation.poll_id))?;
        let kind = FpVar::new_input(ns!(cs, "payload kind"), || Ok(kind))?;
        let lo = FpVar::new_input(ns!(cs, "payload low limb"), || Ok(lo))?;
        let hi = FpVar::new_input(ns!(cs, "payload high limb"), || Ok(hi))?;
        let token = FpVar::new_input(ns!(cs, "one-time token"), || Ok(self.presentation.token))?;
        let tag = FpVar::new_input(ns!(cs, "response tag"), || Ok(self.presentation.tag))?;

        let seed = attrs.get_seed()?;
        let expected_token = h.hash(&[
            FpVar::Constant(F::from(TOKEN_DOMAIN)),
            poll_id.clone(),
            seed.clone(),
        ])?;
        let payload_hash = h.hash(&[FpVar::Constant(F::from(PAYLOAD_DOMAIN)), kind, lo, hi])?;
        let expected_tag = h.hash(&[
            FpVar::Constant(F::from(TAG_DOMAIN)),
            poll_id,
            seed,
            payload_hash,
        ])?;
        expected_token.enforce_equal(&token)?;
        expected_tag.enforce_equal(&tag)
    }

    fn public_inputs(&self) -> Vec<F> {
        let [kind, lo, hi] = self.presentation.payload.to_field_elements::<F>();
        vec![
            self.presentation.poll_id,
            kind,
            lo,
            hi,
            self.presentation.token,
            self.presentation.tag,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        attrs::Attrs,
        com_forest::{gen_forest_memb_crs, ComForestRoots},
        com_tree::{gen_tree_memb_crs, ComTree},
        link::{link_proofs, verif_link_proof, LinkProofCtx, LinkVerifyingKey, PredPublicInputs},
        poseidon_utils::setup_poseidon_params,
        pred::{gen_pred_crs, prove_pred},
        test_util::{
            NameAndBirthYear, NameAndBirthYearVar, TestComSchemePedersen, TestComSchemePedersenG,
            TestTreeH, TestTreeHG, MERKLE_CRH_PARAM,
        },
    };
    use ark_bls12_381::{Bls12_381, Fr};
    use arkworks_utils::Curve;

    #[test]
    fn aves_show_is_one_time_and_response_bound() {
        let mut rng = ark_std::test_rng();
        let params = setup_poseidon_params(Curve::Bls381, 3, 5);
        let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);
        let poll_id = Fr::from(7u8);
        let payload = AvesPayload::ValueCommitment([0u8; 32]);
        let presentation = AvesPresentation::from_attrs::<_, TestComSchemePedersen>(
            &person,
            params.clone(),
            poll_id,
            payload,
        )
        .unwrap();

        let changed_payload = AvesPresentation::from_attrs::<_, TestComSchemePedersen>(
            &person,
            params.clone(),
            poll_id,
            AvesPayload::ValueCommitment([1u8; 32]),
        )
        .unwrap();
        assert_eq!(presentation.token, changed_payload.token);
        assert_ne!(presentation.tag, changed_payload.tag);
        assert_eq!(presentation.entry_id().unwrap().len(), 32);

        let next_poll = AvesPresentation::from_attrs::<_, TestComSchemePedersen>(
            &person,
            params.clone(),
            Fr::from(8u8),
            payload,
        )
        .unwrap();
        assert_ne!(presentation.token, next_poll.token);

        let choice = AvesPresentation::from_attrs::<_, TestComSchemePedersen>(
            &person,
            params.clone(),
            poll_id,
            AvesPayload::Choice(0),
        )
        .unwrap();
        assert_eq!(presentation.token, choice.token);
        assert_ne!(presentation.tag, choice.tag);

        // Issue the committed attributes in a tree and prove the AVES predicate over them.
        let placeholder = AvesShowChecker {
            presentation: AvesPresentation::from_attrs::<_, TestComSchemePedersen>(
                &NameAndBirthYear::default(),
                params.clone(),
                Fr::from(0u8),
                AvesPayload::Choice(0),
            )
            .unwrap(),
            params: params.clone(),
        };
        let pred_pk = gen_pred_crs::<
            _,
            _,
            Bls12_381,
            _,
            NameAndBirthYearVar,
            TestComSchemePedersen,
            TestComSchemePedersenG,
            TestTreeH,
            TestTreeHG,
        >(&mut rng, placeholder)
        .unwrap();
        let pred_vk = pred_pk.prepare_verifying_key();
        let checker = AvesShowChecker {
            presentation: presentation.clone(),
            params: params.clone(),
        };
        let person_com = Attrs::<_, TestComSchemePedersen>::commit(&person);
        let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), 3);
        let auth_path = tree.insert(0, &person_com);
        let root = tree.root();
        let pred_proof = prove_pred(
            &mut rng,
            &pred_pk,
            checker.clone(),
            person.clone(),
            &auth_path,
        )
        .unwrap();

        // The same proving key also works when the public response is a count choice.
        let choice_checker = AvesShowChecker {
            presentation: choice,
            params: params.clone(),
        };
        let choice_proof = prove_pred(
            &mut rng,
            &pred_pk,
            choice_checker.clone(),
            person,
            &auth_path,
        )
        .unwrap();
        assert!(crate::pred::verify_pred(
            &pred_vk,
            &choice_proof,
            &choice_checker,
            &person_com,
            &root,
        )
        .unwrap());

        let tree_pk = gen_tree_memb_crs::<
            _,
            Bls12_381,
            NameAndBirthYear,
            TestComSchemePedersen,
            TestComSchemePedersenG,
            TestTreeH,
            TestTreeHG,
        >(&mut rng, MERKLE_CRH_PARAM.clone(), 3)
        .unwrap();
        let tree_proof = auth_path
            .prove_membership(&mut rng, &tree_pk, &*MERKLE_CRH_PARAM, person_com)
            .unwrap();

        let mut roots = ComForestRoots::new(1);
        roots.roots[0] = root;
        let forest_pk = gen_forest_memb_crs::<
            _,
            Bls12_381,
            NameAndBirthYear,
            TestComSchemePedersen,
            TestComSchemePedersenG,
            TestTreeH,
            TestTreeHG,
        >(&mut rng, 1)
        .unwrap();
        let forest_proof = roots
            .prove_membership(&mut rng, &forest_pk, root, person_com)
            .unwrap();
        let forest_vk = forest_pk.prepare_verifying_key();

        let mut pred_inputs = PredPublicInputs::default();
        pred_inputs.prepare_pred_checker(&pred_vk, &checker);
        let link_vk = LinkVerifyingKey {
            pred_inputs,
            prepared_roots: roots.prepare(&forest_vk).unwrap(),
            forest_verif_key: forest_vk,
            tree_verif_key: tree_pk.prepare_verifying_key(),
            pred_verif_keys: vec![pred_vk],
        };
        let link_ctx = LinkProofCtx {
            attrs_com: person_com,
            merkle_root: root,
            forest_proof,
            tree_proof,
            pred_proofs: vec![pred_proof],
            vk: link_vk,
        };
        let proof = link_proofs(&mut rng, &link_ctx);
        assert!(verif_link_proof(&proof, &link_ctx.vk).unwrap());

        // The verifier must prepare inputs from the response it actually received, not from
        // prover-supplied inputs. Changing that response invalidates the linked proof.
        let mut tampered_checker = checker;
        tampered_checker.presentation.payload = AvesPayload::ValueCommitment([1u8; 32]);
        let mut tampered_vk = link_ctx.vk.clone();
        let mut tampered_inputs = PredPublicInputs::default();
        tampered_inputs.prepare_pred_checker(&tampered_vk.pred_verif_keys[0], &tampered_checker);
        tampered_vk.pred_inputs = tampered_inputs;
        assert!(!verif_link_proof(&proof, &tampered_vk).unwrap());
    }
}
