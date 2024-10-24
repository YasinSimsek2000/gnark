package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type Account struct {
	Nonce   frontend.Variable
	Balance frontend.Variable
	Index   frontend.Variable
	PubKey  eddsa.PublicKey
}

type Transfer struct {
	Amount         frontend.Variable
	Nonce          frontend.Variable
	SenderPubKey   eddsa.PublicKey
	ReceiverPubKey eddsa.PublicKey
	Signature      eddsa.Signature
}

type Circuit struct {
	SenderAccountBefore   Account
	ReceiverAccountBefore Account

	SenderAccountAfter   Account
	ReceiverAccountAfter Account

	Transfer Transfer

	MerkleProofReceiverBefore merkle.MerkleProof // ?
	MerkleProofReceiverAfter  merkle.MerkleProof

	MerkleProofSenderBefore merkle.MerkleProof
	MerkleProofSenderAfter  merkle.MerkleProof

	IndexReceiver frontend.Variable
	IndexSender   frontend.Variable // ?

	RootHashBefore frontend.Variable `gnark:",public"`
	RootHashAfter  frontend.Variable `gnark:",public"`
}

func verifyUpdated(api frontend.API, from, to, fromUpdated, toUpdated Account, amount frontend.Variable) {
	nonceUpdated := api.Add(from.Nonce, 1)
	api.AssertIsEqual(nonceUpdated, fromUpdated.Nonce)
	api.AssertIsLessOrEqual(amount, from.Balance)

	newFromBalanced := api.Sub(from.Balance, amount)
	api.AssertIsEqual(newFromBalanced, fromUpdated.Balance)

	newToBalanced := api.Add(to.Balance, amount)
	api.AssertIsEqual(newToBalanced, toUpdated.Balance)

	api.AssertIsEqual(from.PubKey.A.X, fromUpdated.PubKey.A.X) // ?
	api.AssertIsEqual(from.PubKey.A.Y, fromUpdated.PubKey.A.Y)
	api.AssertIsEqual(to.PubKey.A.X, toUpdated.PubKey.A.X)
	api.AssertIsEqual(to.PubKey.A.Y, toUpdated.PubKey.A.Y)
}

func verifySignature(api frontend.API, t Transfer, hFunc mimc.MiMC) error {
	hFunc.Reset()
	hFunc.Write(t.Nonce, t.Amount, t.SenderPubKey.A.X, t.SenderPubKey.A.Y, t.ReceiverPubKey.A.X, t.ReceiverPubKey.A.Y)
	hTransfer := hFunc.Sum()
	curve, _ := twistededwards.NewEdCurve(api, tedwards.BN254)
	err := eddsa.Verify(curve, t.Signature, hTransfer, t.SenderPubKey, &hFunc)

	if err != nil {
		return err
	}
	return nil
}

func (circuit *Circuit) Define(api frontend.API) error {
	verifyUpdated(api, circuit.SenderAccountBefore, circuit.ReceiverAccountBefore, circuit.SenderAccountAfter, circuit.ReceiverAccountAfter, circuit.Transfer.Amount)
	hFunc, _ := mimc.NewMiMC(api)

	err := verifySignature(api, circuit.Transfer, hFunc)
	if err != nil {
		return err
	}

	//api.AssertIsEqual(circuit.RootHashBefore, circuit.MerkleProofReceiverBefore.RootHash)
	//api.AssertIsEqual(circuit.RootHashAfter, circuit.MerkleProofReceiverAfter.RootHash)
	//api.AssertIsEqual(circuit.RootHashBefore, circuit.MerkleProofSenderBefore.RootHash)
	//api.AssertIsEqual(circuit.RootHashAfter, circuit.MerkleProofSenderAfter.RootHash)

	//circuit.MerkleProofReceiverBefore.VerifyProof(api, &hFunc, circuit.IndexReceiver)
	//circuit.MerkleProofReceiverAfter.VerifyProof(api, &hFunc, circuit.IndexReceiver)
	//circuit.MerkleProofSenderBefore.VerifyProof(api, &hFunc, circuit.IndexSender)
	//circuit.MerkleProofSenderAfter.VerifyProof(api, &hFunc, circuit.IndexSender)

	return nil
}

func Rollup() {
	var circuit Circuit
	R1CS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(R1CS)
	if err != nil {
		panic(err)
	}

	senderPubKey := eddsa.PublicKey{
		A: twistededwards.Point{X: 1, Y: 2},
	}

	receiverPubKey := eddsa.PublicKey{
		A: twistededwards.Point{X: 3, Y: 4},
	}

	senderBefore := Account{
		Nonce:   1,
		Balance: 100,
		Index:   0,
		PubKey:  senderPubKey,
	}

	receiverBefore := Account{
		Nonce:   0,
		Balance: 50,
		Index:   1,
		PubKey:  receiverPubKey,
	}

	senderAfter := Account{
		Nonce:   2,
		Balance: 70,
		Index:   0,
		PubKey:  senderPubKey,
	}

	receiverAfter := Account{
		Nonce:   0,
		Balance: 80,
		Index:   1,
		PubKey:  receiverPubKey,
	}

	transfer := Transfer{
		Amount:         30,
		Nonce:          1,
		SenderPubKey:   senderPubKey,
		ReceiverPubKey: receiverPubKey,
		Signature:      eddsa.Signature{},
	}

	merkleProofSenderBefore := merkle.MerkleProof{
		Path:     []frontend.Variable{1, 2},
		RootHash: 123456,
	}

	merkleProofSenderAfter := merkle.MerkleProof{
		Path:     []frontend.Variable{1, 2},
		RootHash: 654321,
	}

	merkleProofReceiverBefore := merkle.MerkleProof{
		Path:     []frontend.Variable{5, 6},
		RootHash: 123456,
	}

	merkleProofReceiverAfter := merkle.MerkleProof{
		Path:     []frontend.Variable{5, 6},
		RootHash: 654321,
	}

	assignment := &Circuit{
		SenderAccountBefore:       senderBefore,
		ReceiverAccountBefore:     receiverBefore,
		SenderAccountAfter:        senderAfter,
		ReceiverAccountAfter:      receiverAfter,
		Transfer:                  transfer,
		MerkleProofReceiverBefore: merkleProofReceiverBefore,
		MerkleProofReceiverAfter:  merkleProofReceiverAfter,
		MerkleProofSenderBefore:   merkleProofSenderBefore,
		MerkleProofSenderAfter:    merkleProofSenderAfter,
		IndexReceiver:             1,
		IndexSender:               0,
		RootHashBefore:            123456,
		RootHashAfter:             654321,
	}

	witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	proof, err := groth16.Prove(R1CS, pk, witness)
	if err != nil {
		fmt.Printf("Proof creation error: %v\n", err)
		return
	}

	pubWitness, _ := witness.Public()
	err = groth16.Verify(proof, vk, pubWitness)
	if err != nil {
		fmt.Printf("Verification failed: %v\n", err)
	} else {
		fmt.Println("Verification successful!")
	}
}
