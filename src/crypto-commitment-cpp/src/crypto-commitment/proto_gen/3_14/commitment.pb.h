// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: commitment.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_commitment_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_commitment_2eproto

#include <limits>
#include <string>

#include <google/protobuf/port_def.inc>
#if PROTOBUF_VERSION < 3014000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers. Please update
#error your headers.
#endif
#if 3014000 < PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers. Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/port_undef.inc>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/metadata_lite.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/unknown_field_set.h>
#include "crypto-curve/proto_gen/curve_point.pb.switch.h"
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_commitment_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_commitment_2eproto {
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTableField entries[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::AuxiliaryParseTableField aux[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTable schema[2]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::FieldMetadata field_metadata[];
  static const ::PROTOBUF_NAMESPACE_ID::internal::SerializationTable serialization_table[];
  static const ::PROTOBUF_NAMESPACE_ID::uint32 offsets[];
};
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_commitment_2eproto;
namespace safeheron {
namespace proto {
class KGD;
class KGDDefaultTypeInternal;
extern KGDDefaultTypeInternal _KGD_default_instance_;
class KGD_Num;
class KGD_NumDefaultTypeInternal;
extern KGD_NumDefaultTypeInternal _KGD_Num_default_instance_;
}  // namespace proto
}  // namespace safeheron
PROTOBUF_NAMESPACE_OPEN
template<> ::safeheron::proto::KGD* Arena::CreateMaybeMessage<::safeheron::proto::KGD>(Arena*);
template<> ::safeheron::proto::KGD_Num* Arena::CreateMaybeMessage<::safeheron::proto::KGD_Num>(Arena*);
PROTOBUF_NAMESPACE_CLOSE
namespace safeheron {
namespace proto {

// ===================================================================

class KGD PROTOBUF_FINAL :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:safeheron.proto.KGD) */ {
 public:
  inline KGD() : KGD(nullptr) {}
  virtual ~KGD();

  KGD(const KGD& from);
  KGD(KGD&& from) noexcept
    : KGD() {
    *this = ::std::move(from);
  }

  inline KGD& operator=(const KGD& from) {
    CopyFrom(from);
    return *this;
  }
  inline KGD& operator=(KGD&& from) noexcept {
    if (GetArena() == from.GetArena()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return GetMetadataStatic().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return GetMetadataStatic().reflection;
  }
  static const KGD& default_instance();

  static inline const KGD* internal_default_instance() {
    return reinterpret_cast<const KGD*>(
               &_KGD_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(KGD& a, KGD& b) {
    a.Swap(&b);
  }
  inline void Swap(KGD* other) {
    if (other == this) return;
    if (GetArena() == other->GetArena()) {
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(KGD* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetArena() == other->GetArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline KGD* New() const final {
    return CreateMaybeMessage<KGD>(nullptr);
  }

  KGD* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<KGD>(arena);
  }
  void CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void CopyFrom(const KGD& from);
  void MergeFrom(const KGD& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  ::PROTOBUF_NAMESPACE_ID::uint8* _InternalSerialize(
      ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  inline void SharedCtor();
  inline void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(KGD* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "safeheron.proto.KGD";
  }
  protected:
  explicit KGD(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  private:
  static void ArenaDtor(void* object);
  inline void RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  public:

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;
  private:
  static ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadataStatic() {
    ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(&::descriptor_table_commitment_2eproto);
    return ::descriptor_table_commitment_2eproto.file_level_metadata[kIndexInFileMessages];
  }

  public:

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kBlindFactorFieldNumber = 2,
    kYFieldNumber = 1,
  };
  // string blindFactor = 2;
  void clear_blindfactor();
  const std::string& blindfactor() const;
  void set_blindfactor(const std::string& value);
  void set_blindfactor(std::string&& value);
  void set_blindfactor(const char* value);
  void set_blindfactor(const char* value, size_t size);
  std::string* mutable_blindfactor();
  std::string* release_blindfactor();
  void set_allocated_blindfactor(std::string* blindfactor);
  private:
  const std::string& _internal_blindfactor() const;
  void _internal_set_blindfactor(const std::string& value);
  std::string* _internal_mutable_blindfactor();
  public:

  // .safeheron.proto.CurvePoint y = 1;
  bool has_y() const;
  private:
  bool _internal_has_y() const;
  public:
  void clear_y();
  const ::safeheron::proto::CurvePoint& y() const;
  ::safeheron::proto::CurvePoint* release_y();
  ::safeheron::proto::CurvePoint* mutable_y();
  void set_allocated_y(::safeheron::proto::CurvePoint* y);
  private:
  const ::safeheron::proto::CurvePoint& _internal_y() const;
  ::safeheron::proto::CurvePoint* _internal_mutable_y();
  public:
  void unsafe_arena_set_allocated_y(
      ::safeheron::proto::CurvePoint* y);
  ::safeheron::proto::CurvePoint* unsafe_arena_release_y();

  // @@protoc_insertion_point(class_scope:safeheron.proto.KGD)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr blindfactor_;
  ::safeheron::proto::CurvePoint* y_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_commitment_2eproto;
};
// -------------------------------------------------------------------

class KGD_Num PROTOBUF_FINAL :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:safeheron.proto.KGD_Num) */ {
 public:
  inline KGD_Num() : KGD_Num(nullptr) {}
  virtual ~KGD_Num();

  KGD_Num(const KGD_Num& from);
  KGD_Num(KGD_Num&& from) noexcept
    : KGD_Num() {
    *this = ::std::move(from);
  }

  inline KGD_Num& operator=(const KGD_Num& from) {
    CopyFrom(from);
    return *this;
  }
  inline KGD_Num& operator=(KGD_Num&& from) noexcept {
    if (GetArena() == from.GetArena()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return GetMetadataStatic().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return GetMetadataStatic().reflection;
  }
  static const KGD_Num& default_instance();

  static inline const KGD_Num* internal_default_instance() {
    return reinterpret_cast<const KGD_Num*>(
               &_KGD_Num_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    1;

  friend void swap(KGD_Num& a, KGD_Num& b) {
    a.Swap(&b);
  }
  inline void Swap(KGD_Num* other) {
    if (other == this) return;
    if (GetArena() == other->GetArena()) {
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(KGD_Num* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetArena() == other->GetArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline KGD_Num* New() const final {
    return CreateMaybeMessage<KGD_Num>(nullptr);
  }

  KGD_Num* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<KGD_Num>(arena);
  }
  void CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void CopyFrom(const KGD_Num& from);
  void MergeFrom(const KGD_Num& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  ::PROTOBUF_NAMESPACE_ID::uint8* _InternalSerialize(
      ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  inline void SharedCtor();
  inline void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(KGD_Num* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "safeheron.proto.KGD_Num";
  }
  protected:
  explicit KGD_Num(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  private:
  static void ArenaDtor(void* object);
  inline void RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  public:

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;
  private:
  static ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadataStatic() {
    ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(&::descriptor_table_commitment_2eproto);
    return ::descriptor_table_commitment_2eproto.file_level_metadata[kIndexInFileMessages];
  }

  public:

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kNumFieldNumber = 1,
    kBlindFactorFieldNumber = 2,
  };
  // string num = 1;
  void clear_num();
  const std::string& num() const;
  void set_num(const std::string& value);
  void set_num(std::string&& value);
  void set_num(const char* value);
  void set_num(const char* value, size_t size);
  std::string* mutable_num();
  std::string* release_num();
  void set_allocated_num(std::string* num);
  private:
  const std::string& _internal_num() const;
  void _internal_set_num(const std::string& value);
  std::string* _internal_mutable_num();
  public:

  // string blindFactor = 2;
  void clear_blindfactor();
  const std::string& blindfactor() const;
  void set_blindfactor(const std::string& value);
  void set_blindfactor(std::string&& value);
  void set_blindfactor(const char* value);
  void set_blindfactor(const char* value, size_t size);
  std::string* mutable_blindfactor();
  std::string* release_blindfactor();
  void set_allocated_blindfactor(std::string* blindfactor);
  private:
  const std::string& _internal_blindfactor() const;
  void _internal_set_blindfactor(const std::string& value);
  std::string* _internal_mutable_blindfactor();
  public:

  // @@protoc_insertion_point(class_scope:safeheron.proto.KGD_Num)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr num_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr blindfactor_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_commitment_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// KGD

// .safeheron.proto.CurvePoint y = 1;
inline bool KGD::_internal_has_y() const {
  return this != internal_default_instance() && y_ != nullptr;
}
inline bool KGD::has_y() const {
  return _internal_has_y();
}
inline const ::safeheron::proto::CurvePoint& KGD::_internal_y() const {
  const ::safeheron::proto::CurvePoint* p = y_;
  return p != nullptr ? *p : reinterpret_cast<const ::safeheron::proto::CurvePoint&>(
      ::safeheron::proto::_CurvePoint_default_instance_);
}
inline const ::safeheron::proto::CurvePoint& KGD::y() const {
  // @@protoc_insertion_point(field_get:safeheron.proto.KGD.y)
  return _internal_y();
}
inline void KGD::unsafe_arena_set_allocated_y(
    ::safeheron::proto::CurvePoint* y) {
  if (GetArena() == nullptr) {
    delete reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(y_);
  }
  y_ = y;
  if (y) {
    
  } else {
    
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:safeheron.proto.KGD.y)
}
inline ::safeheron::proto::CurvePoint* KGD::release_y() {
  
  ::safeheron::proto::CurvePoint* temp = y_;
  y_ = nullptr;
  if (GetArena() != nullptr) {
    temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
  }
  return temp;
}
inline ::safeheron::proto::CurvePoint* KGD::unsafe_arena_release_y() {
  // @@protoc_insertion_point(field_release:safeheron.proto.KGD.y)
  
  ::safeheron::proto::CurvePoint* temp = y_;
  y_ = nullptr;
  return temp;
}
inline ::safeheron::proto::CurvePoint* KGD::_internal_mutable_y() {
  
  if (y_ == nullptr) {
    auto* p = CreateMaybeMessage<::safeheron::proto::CurvePoint>(GetArena());
    y_ = p;
  }
  return y_;
}
inline ::safeheron::proto::CurvePoint* KGD::mutable_y() {
  // @@protoc_insertion_point(field_mutable:safeheron.proto.KGD.y)
  return _internal_mutable_y();
}
inline void KGD::set_allocated_y(::safeheron::proto::CurvePoint* y) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArena();
  if (message_arena == nullptr) {
    delete reinterpret_cast< ::PROTOBUF_NAMESPACE_ID::MessageLite*>(y_);
  }
  if (y) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
      reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(y)->GetArena();
    if (message_arena != submessage_arena) {
      y = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, y, submessage_arena);
    }
    
  } else {
    
  }
  y_ = y;
  // @@protoc_insertion_point(field_set_allocated:safeheron.proto.KGD.y)
}

// string blindFactor = 2;
inline void KGD::clear_blindfactor() {
  blindfactor_.ClearToEmpty();
}
inline const std::string& KGD::blindfactor() const {
  // @@protoc_insertion_point(field_get:safeheron.proto.KGD.blindFactor)
  return _internal_blindfactor();
}
inline void KGD::set_blindfactor(const std::string& value) {
  _internal_set_blindfactor(value);
  // @@protoc_insertion_point(field_set:safeheron.proto.KGD.blindFactor)
}
inline std::string* KGD::mutable_blindfactor() {
  // @@protoc_insertion_point(field_mutable:safeheron.proto.KGD.blindFactor)
  return _internal_mutable_blindfactor();
}
inline const std::string& KGD::_internal_blindfactor() const {
  return blindfactor_.Get();
}
inline void KGD::_internal_set_blindfactor(const std::string& value) {
  
  blindfactor_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArena());
}
inline void KGD::set_blindfactor(std::string&& value) {
  
  blindfactor_.Set(
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, ::std::move(value), GetArena());
  // @@protoc_insertion_point(field_set_rvalue:safeheron.proto.KGD.blindFactor)
}
inline void KGD::set_blindfactor(const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  
  blindfactor_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, ::std::string(value), GetArena());
  // @@protoc_insertion_point(field_set_char:safeheron.proto.KGD.blindFactor)
}
inline void KGD::set_blindfactor(const char* value,
    size_t size) {
  
  blindfactor_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, ::std::string(
      reinterpret_cast<const char*>(value), size), GetArena());
  // @@protoc_insertion_point(field_set_pointer:safeheron.proto.KGD.blindFactor)
}
inline std::string* KGD::_internal_mutable_blindfactor() {
  
  return blindfactor_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArena());
}
inline std::string* KGD::release_blindfactor() {
  // @@protoc_insertion_point(field_release:safeheron.proto.KGD.blindFactor)
  return blindfactor_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
}
inline void KGD::set_allocated_blindfactor(std::string* blindfactor) {
  if (blindfactor != nullptr) {
    
  } else {
    
  }
  blindfactor_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), blindfactor,
      GetArena());
  // @@protoc_insertion_point(field_set_allocated:safeheron.proto.KGD.blindFactor)
}

// -------------------------------------------------------------------

// KGD_Num

// string num = 1;
inline void KGD_Num::clear_num() {
  num_.ClearToEmpty();
}
inline const std::string& KGD_Num::num() const {
  // @@protoc_insertion_point(field_get:safeheron.proto.KGD_Num.num)
  return _internal_num();
}
inline void KGD_Num::set_num(const std::string& value) {
  _internal_set_num(value);
  // @@protoc_insertion_point(field_set:safeheron.proto.KGD_Num.num)
}
inline std::string* KGD_Num::mutable_num() {
  // @@protoc_insertion_point(field_mutable:safeheron.proto.KGD_Num.num)
  return _internal_mutable_num();
}
inline const std::string& KGD_Num::_internal_num() const {
  return num_.Get();
}
inline void KGD_Num::_internal_set_num(const std::string& value) {
  
  num_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArena());
}
inline void KGD_Num::set_num(std::string&& value) {
  
  num_.Set(
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, ::std::move(value), GetArena());
  // @@protoc_insertion_point(field_set_rvalue:safeheron.proto.KGD_Num.num)
}
inline void KGD_Num::set_num(const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  
  num_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, ::std::string(value), GetArena());
  // @@protoc_insertion_point(field_set_char:safeheron.proto.KGD_Num.num)
}
inline void KGD_Num::set_num(const char* value,
    size_t size) {
  
  num_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, ::std::string(
      reinterpret_cast<const char*>(value), size), GetArena());
  // @@protoc_insertion_point(field_set_pointer:safeheron.proto.KGD_Num.num)
}
inline std::string* KGD_Num::_internal_mutable_num() {
  
  return num_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArena());
}
inline std::string* KGD_Num::release_num() {
  // @@protoc_insertion_point(field_release:safeheron.proto.KGD_Num.num)
  return num_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
}
inline void KGD_Num::set_allocated_num(std::string* num) {
  if (num != nullptr) {
    
  } else {
    
  }
  num_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), num,
      GetArena());
  // @@protoc_insertion_point(field_set_allocated:safeheron.proto.KGD_Num.num)
}

// string blindFactor = 2;
inline void KGD_Num::clear_blindfactor() {
  blindfactor_.ClearToEmpty();
}
inline const std::string& KGD_Num::blindfactor() const {
  // @@protoc_insertion_point(field_get:safeheron.proto.KGD_Num.blindFactor)
  return _internal_blindfactor();
}
inline void KGD_Num::set_blindfactor(const std::string& value) {
  _internal_set_blindfactor(value);
  // @@protoc_insertion_point(field_set:safeheron.proto.KGD_Num.blindFactor)
}
inline std::string* KGD_Num::mutable_blindfactor() {
  // @@protoc_insertion_point(field_mutable:safeheron.proto.KGD_Num.blindFactor)
  return _internal_mutable_blindfactor();
}
inline const std::string& KGD_Num::_internal_blindfactor() const {
  return blindfactor_.Get();
}
inline void KGD_Num::_internal_set_blindfactor(const std::string& value) {
  
  blindfactor_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArena());
}
inline void KGD_Num::set_blindfactor(std::string&& value) {
  
  blindfactor_.Set(
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, ::std::move(value), GetArena());
  // @@protoc_insertion_point(field_set_rvalue:safeheron.proto.KGD_Num.blindFactor)
}
inline void KGD_Num::set_blindfactor(const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  
  blindfactor_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, ::std::string(value), GetArena());
  // @@protoc_insertion_point(field_set_char:safeheron.proto.KGD_Num.blindFactor)
}
inline void KGD_Num::set_blindfactor(const char* value,
    size_t size) {
  
  blindfactor_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, ::std::string(
      reinterpret_cast<const char*>(value), size), GetArena());
  // @@protoc_insertion_point(field_set_pointer:safeheron.proto.KGD_Num.blindFactor)
}
inline std::string* KGD_Num::_internal_mutable_blindfactor() {
  
  return blindfactor_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArena());
}
inline std::string* KGD_Num::release_blindfactor() {
  // @@protoc_insertion_point(field_release:safeheron.proto.KGD_Num.blindFactor)
  return blindfactor_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
}
inline void KGD_Num::set_allocated_blindfactor(std::string* blindfactor) {
  if (blindfactor != nullptr) {
    
  } else {
    
  }
  blindfactor_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), blindfactor,
      GetArena());
  // @@protoc_insertion_point(field_set_allocated:safeheron.proto.KGD_Num.blindFactor)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__
// -------------------------------------------------------------------


// @@protoc_insertion_point(namespace_scope)

}  // namespace proto
}  // namespace safeheron

// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_commitment_2eproto
