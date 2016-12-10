// Code generated by protoc-gen-go.
// source: github.com/ashwinsr/auctions/first_price/first_price.proto
// DO NOT EDIT!

/*
Package main is a generated protocol buffer package.

It is generated from these files:
	github.com/ashwinsr/auctions/first_price/first_price.proto

It has these top-level messages:
	Round1
	Round2
	Gammas
	Deltas
	DiscreteLogEqualityProofs
	Round3
	Phis
*/
package main

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import common_pb "github.com/ashwinsr/auctions/common_pb"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Round1 struct {
	Alphas [][]byte                       `protobuf:"bytes,1,rep,name=alphas,proto3" json:"alphas,omitempty"`
	Betas  [][]byte                       `protobuf:"bytes,2,rep,name=betas,proto3" json:"betas,omitempty"`
	Proofs []*common_pb.EqualsOneOfTwo    `protobuf:"bytes,3,rep,name=proofs" json:"proofs,omitempty"`
	Proof  *common_pb.DiscreteLogEquality `protobuf:"bytes,4,opt,name=proof" json:"proof,omitempty"`
}

func (m *Round1) Reset()                    { *m = Round1{} }
func (m *Round1) String() string            { return proto.CompactTextString(m) }
func (*Round1) ProtoMessage()               {}
func (*Round1) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Round1) GetAlphas() [][]byte {
	if m != nil {
		return m.Alphas
	}
	return nil
}

func (m *Round1) GetBetas() [][]byte {
	if m != nil {
		return m.Betas
	}
	return nil
}

func (m *Round1) GetProofs() []*common_pb.EqualsOneOfTwo {
	if m != nil {
		return m.Proofs
	}
	return nil
}

func (m *Round1) GetProof() *common_pb.DiscreteLogEquality {
	if m != nil {
		return m.Proof
	}
	return nil
}

type Round2 struct {
	DoubleGammas []*Gammas                    `protobuf:"bytes,1,rep,name=doubleGammas" json:"doubleGammas,omitempty"`
	DoubleDeltas []*Deltas                    `protobuf:"bytes,2,rep,name=doubleDeltas" json:"doubleDeltas,omitempty"`
	DoubleProofs []*DiscreteLogEqualityProofs `protobuf:"bytes,3,rep,name=doubleProofs" json:"doubleProofs,omitempty"`
}

func (m *Round2) Reset()                    { *m = Round2{} }
func (m *Round2) String() string            { return proto.CompactTextString(m) }
func (*Round2) ProtoMessage()               {}
func (*Round2) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *Round2) GetDoubleGammas() []*Gammas {
	if m != nil {
		return m.DoubleGammas
	}
	return nil
}

func (m *Round2) GetDoubleDeltas() []*Deltas {
	if m != nil {
		return m.DoubleDeltas
	}
	return nil
}

func (m *Round2) GetDoubleProofs() []*DiscreteLogEqualityProofs {
	if m != nil {
		return m.DoubleProofs
	}
	return nil
}

type Gammas struct {
	Gammas [][]byte `protobuf:"bytes,1,rep,name=gammas,proto3" json:"gammas,omitempty"`
}

func (m *Gammas) Reset()                    { *m = Gammas{} }
func (m *Gammas) String() string            { return proto.CompactTextString(m) }
func (*Gammas) ProtoMessage()               {}
func (*Gammas) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *Gammas) GetGammas() [][]byte {
	if m != nil {
		return m.Gammas
	}
	return nil
}

type Deltas struct {
	Deltas [][]byte `protobuf:"bytes,1,rep,name=deltas,proto3" json:"deltas,omitempty"`
}

func (m *Deltas) Reset()                    { *m = Deltas{} }
func (m *Deltas) String() string            { return proto.CompactTextString(m) }
func (*Deltas) ProtoMessage()               {}
func (*Deltas) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *Deltas) GetDeltas() [][]byte {
	if m != nil {
		return m.Deltas
	}
	return nil
}

type DiscreteLogEqualityProofs struct {
	Proofs []*common_pb.DiscreteLogEquality `protobuf:"bytes,1,rep,name=proofs" json:"proofs,omitempty"`
}

func (m *DiscreteLogEqualityProofs) Reset()                    { *m = DiscreteLogEqualityProofs{} }
func (m *DiscreteLogEqualityProofs) String() string            { return proto.CompactTextString(m) }
func (*DiscreteLogEqualityProofs) ProtoMessage()               {}
func (*DiscreteLogEqualityProofs) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *DiscreteLogEqualityProofs) GetProofs() []*common_pb.DiscreteLogEquality {
	if m != nil {
		return m.Proofs
	}
	return nil
}

type Round3 struct {
	DoublePhis   []*Phis                      `protobuf:"bytes,1,rep,name=doublePhis" json:"doublePhis,omitempty"`
	DoubleProofs []*DiscreteLogEqualityProofs `protobuf:"bytes,2,rep,name=doubleProofs" json:"doubleProofs,omitempty"`
}

func (m *Round3) Reset()                    { *m = Round3{} }
func (m *Round3) String() string            { return proto.CompactTextString(m) }
func (*Round3) ProtoMessage()               {}
func (*Round3) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *Round3) GetDoublePhis() []*Phis {
	if m != nil {
		return m.DoublePhis
	}
	return nil
}

func (m *Round3) GetDoubleProofs() []*DiscreteLogEqualityProofs {
	if m != nil {
		return m.DoubleProofs
	}
	return nil
}

type Phis struct {
	Phis [][]byte `protobuf:"bytes,1,rep,name=phis,proto3" json:"phis,omitempty"`
}

func (m *Phis) Reset()                    { *m = Phis{} }
func (m *Phis) String() string            { return proto.CompactTextString(m) }
func (*Phis) ProtoMessage()               {}
func (*Phis) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *Phis) GetPhis() [][]byte {
	if m != nil {
		return m.Phis
	}
	return nil
}

func init() {
	proto.RegisterType((*Round1)(nil), "main.Round1")
	proto.RegisterType((*Round2)(nil), "main.Round2")
	proto.RegisterType((*Gammas)(nil), "main.Gammas")
	proto.RegisterType((*Deltas)(nil), "main.Deltas")
	proto.RegisterType((*DiscreteLogEqualityProofs)(nil), "main.DiscreteLogEqualityProofs")
	proto.RegisterType((*Round3)(nil), "main.Round3")
	proto.RegisterType((*Phis)(nil), "main.Phis")
}

func init() {
	proto.RegisterFile("github.com/ashwinsr/auctions/first_price/first_price.proto", fileDescriptor0)
}

var fileDescriptor0 = []byte{
	// 357 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x9c, 0x52, 0x31, 0x6f, 0xf2, 0x30,
	0x10, 0x15, 0x10, 0x32, 0x1c, 0x99, 0xac, 0x4f, 0x9f, 0x80, 0xa1, 0x45, 0x99, 0xaa, 0x0e, 0xa1,
	0x40, 0xd5, 0xa1, 0x6b, 0xa9, 0xba, 0x54, 0xa2, 0x72, 0xbb, 0x23, 0x27, 0x18, 0x62, 0x29, 0xb1,
	0xd3, 0xd8, 0x11, 0xe2, 0xd7, 0xf4, 0x37, 0xf4, 0x1f, 0xd6, 0xd8, 0x0e, 0x04, 0xa1, 0xb6, 0x52,
	0xb7, 0xbb, 0xe7, 0xf7, 0xee, 0xde, 0x3d, 0x19, 0xee, 0x37, 0x4c, 0xa5, 0x55, 0x1c, 0x25, 0x22,
	0x1f, 0x13, 0x99, 0x6e, 0x19, 0x97, 0xe5, 0x98, 0x54, 0x89, 0x62, 0x82, 0xcb, 0xf1, 0x9a, 0x95,
	0x52, 0x2d, 0x8b, 0x92, 0x25, 0xb4, 0x59, 0x47, 0x45, 0x29, 0x94, 0x40, 0x5e, 0x4e, 0x18, 0x1f,
	0xce, 0x7e, 0x9c, 0xa0, 0xd1, 0x5c, 0xf0, 0x65, 0x11, 0xbb, 0xca, 0x4a, 0xc3, 0x8f, 0x16, 0xf8,
	0x58, 0x54, 0x7c, 0x35, 0x41, 0xff, 0xc1, 0x27, 0x59, 0x91, 0x12, 0xd9, 0x6f, 0x8d, 0x3a, 0x57,
	0x01, 0x76, 0x1d, 0xfa, 0x07, 0xdd, 0x98, 0x2a, 0x0d, 0xb7, 0x0d, 0x6c, 0x1b, 0x34, 0x01, 0x5f,
	0x4f, 0x10, 0x6b, 0xd9, 0xef, 0x68, 0xb8, 0x37, 0x1d, 0x44, 0x87, 0x0d, 0xd1, 0xe3, 0x7b, 0x45,
	0x32, 0xb9, 0xe0, 0x74, 0xb1, 0x7e, 0xdb, 0x0a, 0xec, 0x88, 0xe8, 0x16, 0xba, 0xa6, 0xea, 0x7b,
	0xa3, 0x96, 0x56, 0x5c, 0x34, 0x14, 0x73, 0x26, 0x93, 0x92, 0x2a, 0xfa, 0x2c, 0x36, 0x46, 0xcc,
	0xd4, 0x0e, 0x5b, 0x72, 0xf8, 0x59, 0x3b, 0x9c, 0xa2, 0x1b, 0x08, 0x56, 0xa2, 0x8a, 0x33, 0xfa,
	0x44, 0xf2, 0xdc, 0xf9, 0xec, 0x4d, 0x83, 0x68, 0x7f, 0x7e, 0x64, 0x31, 0x7c, 0xc2, 0x38, 0x2a,
	0xe6, 0x34, 0xab, 0x4f, 0x38, 0x28, 0x2c, 0x86, 0x4f, 0x18, 0xe8, 0xa1, 0x56, 0xbc, 0x34, 0xaf,
	0xbb, 0x74, 0x8a, 0x73, 0x9b, 0x96, 0x86, 0x4f, 0x44, 0xe1, 0x08, 0x7c, 0x67, 0x40, 0x87, 0xba,
	0x39, 0x9a, 0xd5, 0xa1, 0xda, 0x6e, 0xcf, 0x70, 0x0b, 0x35, 0x63, 0x65, 0xcd, 0x39, 0x86, 0xed,
	0xc2, 0x57, 0x18, 0x7c, 0xbb, 0x0e, 0xdd, 0x1d, 0xd2, 0xb7, 0x19, 0xfc, 0x96, 0xa5, 0x63, 0x87,
	0x3b, 0x97, 0xe5, 0x0c, 0x5d, 0x03, 0x38, 0xcb, 0x29, 0xab, 0xa7, 0x80, 0xbd, 0x72, 0x8f, 0xe0,
	0xc6, 0xeb, 0x59, 0x26, 0xed, 0xbf, 0x64, 0x32, 0x04, 0xcf, 0x0c, 0x43, 0xe0, 0x15, 0xf5, 0xca,
	0x00, 0x9b, 0x3a, 0xf6, 0xcd, 0x67, 0x9c, 0x7d, 0x05, 0x00, 0x00, 0xff, 0xff, 0x48, 0x1a, 0xe5,
	0x77, 0x05, 0x03, 0x00, 0x00,
}
