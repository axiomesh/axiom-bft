// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: messages.proto

package consensus

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type TransactionSet struct {
	TxList    []*Transaction `protobuf:"bytes,1,rep,name=tx_list,json=txList,proto3" json:"tx_list,omitempty"`
	HashList  []string       `protobuf:"bytes,2,rep,name=hash_list,json=hashList,proto3" json:"hash_list,omitempty"`
	LocalList []bool         `protobuf:"varint,3,rep,packed,name=local_list,json=localList,proto3" json:"local_list,omitempty"`
}

func (m *TransactionSet) Reset()         { *m = TransactionSet{} }
func (m *TransactionSet) String() string { return proto.CompactTextString(m) }
func (*TransactionSet) ProtoMessage()    {}
func (*TransactionSet) Descriptor() ([]byte, []int) {
	return fileDescriptor_4dc296cbfe5ffcd5, []int{0}
}
func (m *TransactionSet) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *TransactionSet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_TransactionSet.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *TransactionSet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TransactionSet.Merge(m, src)
}
func (m *TransactionSet) XXX_Size() int {
	return m.Size()
}
func (m *TransactionSet) XXX_DiscardUnknown() {
	xxx_messageInfo_TransactionSet.DiscardUnknown(m)
}

var xxx_messageInfo_TransactionSet proto.InternalMessageInfo

func (m *TransactionSet) GetTxList() []*Transaction {
	if m != nil {
		return m.TxList
	}
	return nil
}

func (m *TransactionSet) GetHashList() []string {
	if m != nil {
		return m.HashList
	}
	return nil
}

func (m *TransactionSet) GetLocalList() []bool {
	if m != nil {
		return m.LocalList
	}
	return nil
}

func init() {
	proto.RegisterType((*TransactionSet)(nil), "consensus.transaction_set")
}

func init() { proto.RegisterFile("messages.proto", fileDescriptor_4dc296cbfe5ffcd5) }

var fileDescriptor_4dc296cbfe5ffcd5 = []byte{
	// 184 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0xcb, 0x4d, 0x2d, 0x2e,
	0x4e, 0x4c, 0x4f, 0x2d, 0xd6, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x4c, 0xce, 0xcf, 0x2b,
	0x4e, 0xcd, 0x2b, 0x2e, 0x2d, 0x96, 0x12, 0x2c, 0x29, 0x4a, 0xcc, 0x2b, 0x4e, 0x4c, 0x2e, 0xc9,
	0xcc, 0xcf, 0x83, 0xc8, 0x2a, 0xd5, 0x71, 0xf1, 0x23, 0x09, 0xc6, 0x17, 0xa7, 0x96, 0x08, 0xe9,
	0x73, 0xb1, 0x97, 0x54, 0xc4, 0xe7, 0x64, 0x16, 0x97, 0x48, 0x30, 0x2a, 0x30, 0x6b, 0x70, 0x1b,
	0x89, 0xe9, 0xc1, 0x8d, 0xd0, 0x0b, 0x41, 0x28, 0x0e, 0x62, 0x2b, 0xa9, 0xf0, 0xc9, 0x2c, 0x2e,
	0x11, 0x92, 0xe6, 0xe2, 0xcc, 0x48, 0x2c, 0xce, 0x80, 0x68, 0x61, 0x52, 0x60, 0xd6, 0xe0, 0x0c,
	0xe2, 0x00, 0x09, 0x80, 0x25, 0x65, 0xb9, 0xb8, 0x72, 0xf2, 0x93, 0x13, 0x73, 0x20, 0xb2, 0xcc,
	0x0a, 0xcc, 0x1a, 0x1c, 0x41, 0x9c, 0x60, 0x11, 0x90, 0xb4, 0x93, 0xc4, 0x89, 0x47, 0x72, 0x8c,
	0x17, 0x1e, 0xc9, 0x31, 0x3e, 0x78, 0x24, 0xc7, 0x38, 0xe1, 0xb1, 0x1c, 0xc3, 0x85, 0xc7, 0x72,
	0x0c, 0x37, 0x1e, 0xcb, 0x31, 0x24, 0xb1, 0x81, 0x1d, 0x68, 0x0c, 0x08, 0x00, 0x00, 0xff, 0xff,
	0x18, 0xdf, 0x0a, 0x0b, 0xd0, 0x00, 0x00, 0x00,
}

func (m *TransactionSet) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *TransactionSet) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *TransactionSet) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.LocalList) > 0 {
		for iNdEx := len(m.LocalList) - 1; iNdEx >= 0; iNdEx-- {
			i--
			if m.LocalList[iNdEx] {
				dAtA[i] = 1
			} else {
				dAtA[i] = 0
			}
		}
		i = encodeVarintMessages(dAtA, i, uint64(len(m.LocalList)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.HashList) > 0 {
		for iNdEx := len(m.HashList) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.HashList[iNdEx])
			copy(dAtA[i:], m.HashList[iNdEx])
			i = encodeVarintMessages(dAtA, i, uint64(len(m.HashList[iNdEx])))
			i--
			dAtA[i] = 0x12
		}
	}
	if len(m.TxList) > 0 {
		for iNdEx := len(m.TxList) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.TxList[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintMessages(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func encodeVarintMessages(dAtA []byte, offset int, v uint64) int {
	offset -= sovMessages(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *TransactionSet) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.TxList) > 0 {
		for _, e := range m.TxList {
			l = e.Size()
			n += 1 + l + sovMessages(uint64(l))
		}
	}
	if len(m.HashList) > 0 {
		for _, s := range m.HashList {
			l = len(s)
			n += 1 + l + sovMessages(uint64(l))
		}
	}
	if len(m.LocalList) > 0 {
		n += 1 + sovMessages(uint64(len(m.LocalList))) + len(m.LocalList)*1
	}
	return n
}

func sovMessages(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozMessages(x uint64) (n int) {
	return sovMessages(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *TransactionSet) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMessages
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: transaction_set: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: transaction_set: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field TxList", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessages
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthMessages
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthMessages
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.TxList = append(m.TxList, &Transaction{})
			if err := m.TxList[len(m.TxList)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field HashList", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessages
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthMessages
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthMessages
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.HashList = append(m.HashList, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		case 3:
			if wireType == 0 {
				var v int
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowMessages
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					v |= int(b&0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				m.LocalList = append(m.LocalList, bool(v != 0))
			} else if wireType == 2 {
				var packedLen int
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowMessages
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					packedLen |= int(b&0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				if packedLen < 0 {
					return ErrInvalidLengthMessages
				}
				postIndex := iNdEx + packedLen
				if postIndex < 0 {
					return ErrInvalidLengthMessages
				}
				if postIndex > l {
					return io.ErrUnexpectedEOF
				}
				var elementCount int
				elementCount = packedLen
				if elementCount != 0 && len(m.LocalList) == 0 {
					m.LocalList = make([]bool, 0, elementCount)
				}
				for iNdEx < postIndex {
					var v int
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowMessages
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						v |= int(b&0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					m.LocalList = append(m.LocalList, bool(v != 0))
				}
			} else {
				return fmt.Errorf("proto: wrong wireType = %d for field LocalList", wireType)
			}
		default:
			iNdEx = preIndex
			skippy, err := skipMessages(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthMessages
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipMessages(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowMessages
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMessages
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMessages
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthMessages
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupMessages
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthMessages
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthMessages        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowMessages          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupMessages = fmt.Errorf("proto: unexpected end of group")
)