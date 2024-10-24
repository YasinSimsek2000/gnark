package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type EquationCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

// Define f(x) = x^3 + x + 5
func (circuit *EquationCircuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	x3Plus := api.Add(x3, circuit.X, 5)
	api.AssertIsEqual(x3Plus, circuit.Y)
	return nil
}

func Equation() {
	var poly EquationCircuit
	R1CS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &poly)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(R1CS)
	if err != nil {
		panic(err)
	}

	fmt.Printf("pk.NbG1(): %v\n", pk.NbG1())
	fmt.Printf("pk.NbG2(): %v\n", pk.NbG2())

	assignment := &EquationCircuit{
		X: 3,
		Y: 35,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(R1CS, pk, witness)
	if err != nil {
		fmt.Printf("İspat üretme hatası: %v\n", err)
		return
	}

	pubWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	result := groth16.Verify(proof, vk, pubWitness)
	if result == nil {
		fmt.Println("Successful.")
	} else {
		fmt.Println("Failed.")
	}
}
