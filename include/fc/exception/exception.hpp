#pragma once
/**
 *  @file exception.hpp
 *  @brief Defines exception's used by fc
 */
#include <fc/log/logger.hpp>
#include <fc/optional.hpp>
#include <exception>
#include <functional>
#include <unordered_map>
#include <boost/core/typeinfo.hpp>
#include <boost/interprocess/exceptions.hpp>

[[ noreturn ]] void vm_api_throw_exception(int type, const char* fmt, ...);

namespace fc
{
   namespace detail { class exception_impl; }
   enum exception_type {
      enum_exception,
      enum_timeout_exception,
      enum_file_not_found_exception,
      enum_parse_error_exception,
      enum_invalid_arg_exception,
      enum_key_not_found_exception,
      enum_bad_cast_exception,
      enum_out_of_range_exception,
      enum_invalid_operation_exception,
      enum_unknown_host_exception,
      enum_canceled_exception,
      enum_assert_exception,
      enum_eof_exception,
      enum_null_optional,
      enum_udt_exception,
      enum_aes_exception,
      enum_overflow_exception,
      enum_underflow_exception,
      enum_divide_by_zero_exception,

      enum_chain_exception,
      enum_chain_type_exception,
      enum_name_type_exception,
      enum_public_key_type_exception,
      enum_private_key_type_exception,
      enum_authority_type_exception,
      enum_action_type_exception,
      enum_transaction_type_exception,
      enum_abi_type_exception,
      enum_block_id_type_exception,
      enum_transaction_id_type_exception,
      enum_packed_transaction_type_exception,
      enum_asset_type_exception,
      enum_chain_id_type_exception,
      enum_fixed_key_type_exception,
      enum_symbol_type_exception,
      enum_fork_database_exception,
      enum_fork_db_block_not_found,
      enum_block_validate_exception,
      enum_unlinkable_block_exception,
      enum_block_tx_output_exception,
      enum_block_concurrency_exception,
      enum_block_lock_exception,
      enum_block_resource_exhausted,
      enum_block_too_old_exception,
      enum_block_from_the_future,
      enum_wrong_signing_key,
      enum_wrong_producer,
      enum_transaction_exception,
      enum_tx_decompression_error,
      enum_tx_no_action,
      enum_tx_no_auths,
      enum_cfa_irrelevant_auth,
      enum_expired_tx_exception,
      enum_tx_exp_too_far_exception,
      enum_invalid_ref_block_exception,
      enum_tx_duplicate,
      enum_deferred_tx_duplicate,
      enum_cfa_inside_generated_tx,
      enum_tx_not_found,
      enum_too_many_tx_at_once,
      enum_tx_too_big,
      enum_unknown_transaction_compression,
      enum_action_validate_exception,
      enum_account_name_exists_exception,
      enum_invalid_action_args_exception,
      enum_eosio_assert_message_exception,
      enum_eosio_assert_code_exception,
      enum_action_not_found_exception,
      enum_action_data_and_struct_mismatch,
      enum_unaccessible_api,
      enum_abort_called,
      enum_inline_action_too_big,
      enum_database_exception,
      enum_permission_query_exception,
      enum_account_query_exception,
      enum_contract_table_query_exception,
      enum_contract_query_exception,
      enum_guard_exception,
      enum_database_guard_exception,
      enum_reversible_guard_exception,
      enum_wasm_exception,
      enum_page_memory_error,
      enum_wasm_execution_error,
      enum_wasm_serialization_error,
      enum_overlapping_memory_error,
      enum_binaryen_exception,
      enum_resource_exhausted_exception,
      enum_ram_usage_exceeded,
      enum_tx_net_usage_exceeded,
      enum_block_net_usage_exceeded,
      enum_tx_cpu_usage_exceeded,
      enum_block_cpu_usage_exceeded,
      enum_deadline_exception,
      enum_greylist_net_usage_exceeded,
      enum_greylist_cpu_usage_exceeded,
      enum_leeway_deadline_exception,
      enum_authorization_exception,
      enum_tx_duplicate_sig,
      enum_tx_irrelevant_sig,
      enum_unsatisfied_authorization,
      enum_missing_auth_exception,
      enum_irrelevant_auth_exception,
      enum_insufficient_delay_exception,
      enum_invalid_permission,
      enum_unlinkable_min_permission_action,
      enum_invalid_parent_permission,
      enum_misc_exception,
      enum_rate_limiting_state_inconsistent,
      enum_unknown_block_exception,
      enum_unknown_transaction_exception,
      enum_fixed_reversible_db_exception,
      enum_extract_genesis_state_exception,
      enum_subjective_block_production_exception,
      enum_multiple_voter_info,
      enum_unsupported_feature,
      enum_node_management_success,
      enum_plugin_exception,
      enum_missing_chain_api_plugin_exception,
      enum_missing_wallet_api_plugin_exception,
      enum_missing_history_api_plugin_exception,
      enum_missing_net_api_plugin_exception,
      enum_missing_chain_plugin_exception,
      enum_plugin_config_exception,
      enum_wallet_exception,
      enum_wallet_exist_exception,
      enum_wallet_nonexistent_exception,
      enum_wallet_locked_exception,
      enum_wallet_missing_pub_key_exception,
      enum_wallet_invalid_password_exception,
      enum_wallet_not_available_exception,
      enum_wallet_unlocked_exception,
      enum_key_exist_exception,
      enum_key_nonexistent_exception,
      enum_unsupported_key_type_exception,
      enum_invalid_lock_timeout_exception,
      enum_secure_enclave_exception,
      enum_whitelist_blacklist_exception,
      enum_actor_whitelist_exception,
      enum_actor_blacklist_exception,
      enum_contract_whitelist_exception,
      enum_contract_blacklist_exception,
      enum_action_blacklist_exception,
      enum_key_blacklist_exception,
      enum_controller_emit_signal_exception,
      enum_checkpoint_exception,
      enum_abi_exception,
      enum_abi_not_found_exception,
      enum_invalid_ricardian_clause_exception,
      enum_invalid_ricardian_action_exception,
      enum_invalid_type_inside_abi,
      enum_duplicate_abi_type_def_exception,
      enum_duplicate_abi_struct_def_exception,
      enum_duplicate_abi_action_def_exception,
      enum_duplicate_abi_table_def_exception,
      enum_duplicate_abi_err_msg_def_exception,
      enum_abi_serialization_deadline_exception,
      enum_abi_recursion_depth_exception,
      enum_abi_circular_def_exception,
      enum_unpack_exception,
      enum_pack_exception,
      enum_duplicate_abi_variant_def_exception,
      enum_unsupported_abi_version_exception,
      enum_contract_exception,
      enum_invalid_table_payer,
      enum_table_access_violation,
      enum_invalid_table_iterator,
      enum_table_not_in_cache,
      enum_table_operation_not_permitted,
      enum_invalid_contract_vm_type,
      enum_invalid_contract_vm_version,
      enum_set_exact_code,
      enum_wast_file_not_found,
      enum_abi_file_not_found,
      enum_producer_exception,
      enum_producer_priv_key_not_found,
      enum_missing_pending_block_state,
      enum_producer_double_confirm,
      enum_producer_schedule_exception,
      enum_producer_not_in_schedule,
      enum_reversible_blocks_exception,
      enum_invalid_reversible_blocks_dir,
      enum_reversible_blocks_backup_dir_exist,
      enum_gap_in_reversible_blocks_db,
      enum_block_log_exception,
      enum_block_log_unsupported_version,
      enum_block_log_append_fail,
      enum_block_log_not_found,
      enum_block_log_backup_dir_exist,
      enum_http_exception,
      enum_invalid_http_client_root_cert,
      enum_invalid_http_response,
      enum_resolved_to_multiple_ports,
      enum_fail_to_resolve_host,
      enum_http_request_fail,
      enum_invalid_http_request,
      enum_resource_limit_exception,
      enum_mongo_db_exception,
      enum_mongo_db_insert_fail,
      enum_mongo_db_update_fail,
      enum_contract_api_exception,
      enum_crypto_api_exception,
      enum_db_api_exception,
      enum_arithmetic_exception,
      enum_abi_generation_exception,
   };

   enum exception_code
   {
       /** for exceptions we threw that don't have an assigned code */
       unspecified_exception_code        = 0,
       unhandled_exception_code          = 1, ///< for unhandled 3rd party exceptions
       timeout_exception_code            = 2, ///< timeout exceptions
       file_not_found_exception_code     = 3,
       parse_error_exception_code        = 4,
       invalid_arg_exception_code        = 5,
       key_not_found_exception_code      = 6,
       bad_cast_exception_code           = 7,
       out_of_range_exception_code       = 8,
       canceled_exception_code           = 9,
       assert_exception_code             = 10,
       eof_exception_code                = 11,
       std_exception_code                = 13,
       invalid_operation_exception_code  = 14,
       unknown_host_exception_code       = 15,
       null_optional_code                = 16,
       udt_error_code                    = 17,
       aes_error_code                    = 18,
       overflow_code                     = 19,
       underflow_code                    = 20,
       divide_by_zero_code               = 21
   };

   /**
    *  @brief Used to generate a useful error report when an exception is thrown.
    *  @ingroup serializable
    *
    *  At each level in the stack where the exception is caught and rethrown a
    *  new log_message is added to the exception.
    *
    *  exception's are designed to be serialized to a variant and
    *  deserialized from an variant.
    *
    *  @see FC_THROW_EXCEPTION
    *  @see FC_RETHROW_EXCEPTION
    *  @see FC_RETHROW_EXCEPTIONS
    */
   class exception
   {
      public:
         enum code_enum
         {
            code_value = unspecified_exception_code
         };

         exception( int64_t code = unspecified_exception_code,
                    const std::string& name_value = "exception",
                    const std::string& what_value = "unspecified");
         exception( log_message&&, int64_t code = unspecified_exception_code,
                                   const std::string& name_value = "exception",
                                   const std::string& what_value = "unspecified");
         exception( log_messages&&, int64_t code = unspecified_exception_code,
                                    const std::string& name_value = "exception",
                                    const std::string& what_value = "unspecified");
         exception( const log_messages&,
                    int64_t code = unspecified_exception_code,
                    const std::string& name_value = "exception",
                    const std::string& what_value = "unspecified");
         exception( const exception& e );
         exception( exception&& e );
         virtual ~exception();

         const char*          name()const throw();
         int64_t              code()const throw();
         virtual const char*  what()const throw();

         /**
          *   @return a reference to log messages that have
          *   been added to this log.
          */
         const log_messages&  get_log()const;
         void                 append_log( log_message m );

         /**
          *   Generates a detailed string including file, line, method,
          *   and other information that is generally only useful for
          *   developers.
          */
         std::string to_detail_string( log_level ll = log_level::all )const;

         /**
          *   Generates a user-friendly error report.
          */
         std::string to_string( log_level ll = log_level::info  )const;

         /**
          *   Generates a user-friendly error report.
          */
         std::string top_message( )const;

         /**
          *  Throw this exception as its most derived type.
          *
          *  @note does not return.
          */
         virtual NO_RETURN void     dynamic_rethrow_exception()const;

         /**
          *  This is equivalent to:
          *  @code
          *   try { throwAsDynamic_exception(); }
          *   catch( ... ) { return std::current_exception(); }
          *  @endcode
          */
          virtual std::shared_ptr<exception> dynamic_copy_exception()const;

         friend void to_variant( const exception& e, variant& v );
         friend void from_variant( const variant& e, exception& ll );

         exception& operator=( const exception& copy );
         exception& operator=( exception&& copy );
         static exception* current_exception;
      protected:
         std::unique_ptr<detail::exception_impl> my;
   };

   void to_variant( const exception& e, variant& v );
   void from_variant( const variant& e, exception& ll );
   typedef std::shared_ptr<exception> exception_ptr;

   typedef optional<exception> oexception;


   /**
    *  @brief re-thrown whenever an unhandled exception is caught.
    *  @ingroup serializable
    *  Any exceptions thrown by 3rd party libraries that are not
    *  caught get wrapped in an unhandled_exception exception.
    *
    *  The original exception is captured as a std::exception_ptr
    *  which may be rethrown.  The std::exception_ptr does not
    *  propgate across process boundaries.
    */
   class unhandled_exception : public exception
   {
      public:
       enum code_enum {
          code_value = unhandled_exception_code,
       };
       unhandled_exception( log_message&& m, std::exception_ptr e = std::current_exception() );
       unhandled_exception( log_messages );
       unhandled_exception( const exception&  );

       std::exception_ptr get_inner_exception()const;

       virtual NO_RETURN void               dynamic_rethrow_exception()const;
       virtual std::shared_ptr<exception>   dynamic_copy_exception()const;
      private:
       std::exception_ptr _inner;
   };

   template<typename T>
   fc::exception_ptr copy_exception( T&& e )
   {
#if defined(_MSC_VER) && (_MSC_VER < 1700)
     return std::make_shared<unhandled_exception>( log_message(),
                                                   std::copy_exception(fc::forward<T>(e)) );
#else
     return std::make_shared<unhandled_exception>( log_message(),
                                                   std::make_exception_ptr(fc::forward<T>(e)) );
#endif
   }


   class exception_factory
   {
      public:
        struct base_exception_builder
        {
           virtual NO_RETURN void rethrow( const exception& e )const = 0;
        };

        template<typename T>
        struct exception_builder : public base_exception_builder
        {
           virtual NO_RETURN void rethrow( const exception& e )const override
           {
              throw T( e.code(), e.name(), e.what() );
           }
        };

        template<typename T>
        void register_exception()
        {
           static exception_builder<T> builder;
           auto itr = _registered_exceptions.find( T::code_value );
           assert( itr == _registered_exceptions.end() );
           (void)itr; // in release builds this hides warnings
           _registered_exceptions[T::code_value] = &builder;
        }

        void NO_RETURN rethrow( const exception& e )const;

        static exception_factory& instance()
        {
           static exception_factory once;
           return once;
        }

      private:
        std::unordered_map<int64_t,base_exception_builder*> _registered_exceptions;
   };
#define FC_REGISTER_EXCEPTION(r, unused, base) \
   fc::exception_factory::instance().register_exception<base>();

#define FC_REGISTER_EXCEPTIONS( SEQ )\
     \
   static bool exception_init = []()->bool{ \
    BOOST_PP_SEQ_FOR_EACH( FC_REGISTER_EXCEPTION, v, SEQ )  \
      return true; \
   }();  \


#define FC_DECLARE_DERIVED_EXCEPTION( TYPE, BASE, CODE, WHAT ) \
   class TYPE : public BASE  \
   { \
      public: \
       enum code_enum { \
          code_value = CODE, \
       }; \
       explicit TYPE( int64_t code, const std::string& name_value, const std::string& what_value ) \
       :BASE( code, name_value, what_value ){} \
       explicit TYPE( fc::log_message&& m, int64_t code, const std::string& name_value, const std::string& what_value ) \
       :BASE( std::move(m), code, name_value, what_value ){} \
       explicit TYPE( fc::log_messages&& m, int64_t code, const std::string& name_value, const std::string& what_value )\
       :BASE( std::move(m), code, name_value, what_value ){}\
       explicit TYPE( const fc::log_messages& m, int64_t code, const std::string& name_value, const std::string& what_value )\
       :BASE( m, code, name_value, what_value ){}\
       TYPE( const std::string& what_value, const fc::log_messages& m ) \
       :BASE( m, CODE, BOOST_PP_STRINGIZE(TYPE), what_value ){} \
       TYPE( fc::log_message&& m ) \
       :BASE( fc::move(m), CODE, BOOST_PP_STRINGIZE(TYPE), WHAT ){}\
       TYPE( fc::log_messages msgs ) \
       :BASE( fc::move( msgs ), CODE, BOOST_PP_STRINGIZE(TYPE), WHAT ) {} \
       TYPE( const TYPE& c ) \
       :BASE(c){} \
       TYPE( const BASE& c ) \
       :BASE(c){} \
       TYPE():BASE(CODE, BOOST_PP_STRINGIZE(TYPE), WHAT){}\
       \
       virtual std::shared_ptr<fc::exception> dynamic_copy_exception()const\
       { return std::make_shared<TYPE>( *this ); } \
       virtual NO_RETURN void     dynamic_rethrow_exception()const \
       { if( code() == CODE ) throw *this;\
         else fc::exception::dynamic_rethrow_exception(); \
       } \
   };

  #define FC_DECLARE_EXCEPTION( TYPE, CODE, WHAT ) \
      FC_DECLARE_DERIVED_EXCEPTION( TYPE, fc::exception, CODE, WHAT )

  FC_DECLARE_EXCEPTION( timeout_exception, timeout_exception_code, "Timeout" );
  FC_DECLARE_EXCEPTION( file_not_found_exception, file_not_found_exception_code, "File Not Found" );
  /**
   * @brief report's parse errors
   */
  FC_DECLARE_EXCEPTION( parse_error_exception, parse_error_exception_code, "Parse Error" );
  FC_DECLARE_EXCEPTION( invalid_arg_exception, invalid_arg_exception_code, "Invalid Argument" );
  /**
   * @brief reports when a key, guid, or other item is not found.
   */
  FC_DECLARE_EXCEPTION( key_not_found_exception, key_not_found_exception_code, "Key Not Found" );
  FC_DECLARE_EXCEPTION( bad_cast_exception, bad_cast_exception_code, "Bad Cast" );
  FC_DECLARE_EXCEPTION( out_of_range_exception, out_of_range_exception_code, "Out of Range" );

  /** @brief if an operation is unsupported or not valid this may be thrown */
  FC_DECLARE_EXCEPTION( invalid_operation_exception,
                        invalid_operation_exception_code,
                        "Invalid Operation" );
  /** @brief if an host name can not be resolved this may be thrown */
  FC_DECLARE_EXCEPTION( unknown_host_exception,
                         unknown_host_exception_code,
                         "Unknown Host" );

  /**
   *  @brief used to report a canceled Operation
   */
  FC_DECLARE_EXCEPTION( canceled_exception, canceled_exception_code, "Canceled" );
  /**
   *  @brief used inplace of assert() to report violations of pre conditions.
   */
  FC_DECLARE_EXCEPTION( assert_exception, assert_exception_code, "Assert Exception" );
  FC_DECLARE_EXCEPTION( eof_exception, eof_exception_code, "End Of File" );
  FC_DECLARE_EXCEPTION( null_optional, null_optional_code, "null optional" );
  FC_DECLARE_EXCEPTION( udt_exception, udt_error_code, "UDT error" );
  FC_DECLARE_EXCEPTION( aes_exception, aes_error_code, "AES error" );
  FC_DECLARE_EXCEPTION( overflow_exception, overflow_code, "Integer Overflow" );
  FC_DECLARE_EXCEPTION( underflow_exception, underflow_code, "Integer Underflow" );
  FC_DECLARE_EXCEPTION( divide_by_zero_exception, divide_by_zero_code, "Integer Divide By Zero" );

  std::string except_str();

  void record_assert_trip(
     const char* filename,
     uint32_t lineno,
     const char* expr
     );

  extern bool enable_record_assert_trip;
} // namespace fc

#if __APPLE__
    #define LIKELY(x)    __builtin_expect((long)!!(x), 1L)
    #define UNLIKELY(x)  __builtin_expect((long)!!(x), 0L)
#else
    #define LIKELY(x)   (x)
    #define UNLIKELY(x) (x)
#endif

/**
 *@brief: Workaround for varying preprocessing behavior between MSVC and gcc
 */
#define FC_EXPAND_MACRO( x ) x
/**
 *  @brief Checks a condition and throws an assert_exception if the test is FALSE
 */
#define FC_ASSERT( TEST, ... ) \
  FC_EXPAND_MACRO( \
    FC_MULTILINE_MACRO_BEGIN \
      if( UNLIKELY(!(TEST)) ) \
      {                                                                      \
        if( fc::enable_record_assert_trip )                                  \
           fc::record_assert_trip( __FILE__, __LINE__, #TEST );              \
        FC_THROW_EXCEPTION( assert_exception, #TEST ": "  __VA_ARGS__ ); \
      }                                                                      \
    FC_MULTILINE_MACRO_END \
  )

#define FC_CAPTURE_AND_THROW( EXCEPTION_TYPE, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
    throw EXCEPTION_TYPE( FC_LOG_MESSAGE( error, "", FC_FORMAT_ARG_PARAMS(__VA_ARGS__) ) ); \
  FC_MULTILINE_MACRO_END

//#define FC_THROW( FORMAT, ... )
// FC_INDIRECT_EXPAND workas around a bug in Visual C++ variadic macro processing that prevents it
// from separating __VA_ARGS__ into separate tokens
#define FC_INDIRECT_EXPAND(MACRO, ARGS) MACRO ARGS
#define FC_THROW(  ... ) \
  FC_MULTILINE_MACRO_BEGIN \
    throw fc::exception( FC_INDIRECT_EXPAND(FC_LOG_MESSAGE, ( error, __VA_ARGS__ )) );  \
  FC_MULTILINE_MACRO_END

#define FC_EXCEPTION( EXCEPTION_TYPE, FORMAT, ... ) \
    EXCEPTION_TYPE( FC_LOG_MESSAGE( error, FORMAT, __VA_ARGS__ ) )
/**
 *  @def FC_THROW_EXCEPTION( EXCEPTION, FORMAT, ... )
 *  @param EXCEPTION a class in the Phoenix::Athena::API namespace that inherits
 *  @param format - a const char* string with "${keys}"
 */
#if 0

#define FC_THROW_EXCEPTION( EXCEPTION, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
    throw EXCEPTION( FC_LOG_MESSAGE( error, FORMAT, __VA_ARGS__ ) ); \
  FC_MULTILINE_MACRO_END

#else

#define FC_THROW_EXCEPTION( EXCEPTION, FORMAT, ... ) \
      {                                              \
             vm_api_throw_exception( fc::exception_type::enum_##EXCEPTION, FC_LOG_MESSAGE( error, FORMAT, __VA_ARGS__ ).get_message().c_str() ); \
      }
#endif

/**
 *  @def FC_RETHROW_EXCEPTION(ER,LOG_LEVEL,FORMAT,...)
 *  @brief Appends a log_message to the exception ER and rethrows it.
 */
#define FC_RETHROW_EXCEPTION( ER, LOG_LEVEL, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
    ER.append_log( FC_LOG_MESSAGE( LOG_LEVEL, FORMAT, __VA_ARGS__ ) ); \
    throw; \
  FC_MULTILINE_MACRO_END

#define FC_LOG_AND_RETHROW( )  \
   catch( const boost::interprocess::bad_alloc& ) {\
      throw;\
   } catch( fc::exception& er ) { \
      wlog( "${details}", ("details",er.to_detail_string()) ); \
      FC_RETHROW_EXCEPTION( er, warn, "rethrow" ); \
   } catch( const std::exception& e ) {  \
      fc::exception fce( \
                FC_LOG_MESSAGE( warn, "rethrow ${what}: ", ("what",e.what())), \
                fc::std_exception_code,\
                BOOST_CORE_TYPEID(e).name(), \
                e.what() ) ; \
      wlog( "${details}", ("details",fce.to_detail_string()) ); \
      throw fce;\
   } catch( ... ) {  \
      fc::unhandled_exception e( \
                FC_LOG_MESSAGE( warn, "rethrow"), \
                std::current_exception() ); \
      wlog( "${details}", ("details",e.to_detail_string()) ); \
      throw e; \
   }

#define FC_CAPTURE_LOG_AND_RETHROW( ... )  \
   catch( const boost::interprocess::bad_alloc& ) {\
      throw;\
   } catch( fc::exception& er ) { \
      wlog( "${details}", ("details",er.to_detail_string()) ); \
      wdump( __VA_ARGS__ ); \
      FC_RETHROW_EXCEPTION( er, warn, "rethrow", FC_FORMAT_ARG_PARAMS(__VA_ARGS__) ); \
   } catch( const std::exception& e ) {  \
      fc::exception fce( \
                FC_LOG_MESSAGE( warn, "rethrow ${what}: ", FC_FORMAT_ARG_PARAMS( __VA_ARGS__ )("what",e.what())), \
                fc::std_exception_code,\
                BOOST_CORE_TYPEID(e).name(), \
                e.what() ) ; \
      wlog( "${details}", ("details",fce.to_detail_string()) ); \
      wdump( __VA_ARGS__ ); \
      throw fce;\
   } catch( ... ) {  \
      fc::unhandled_exception e( \
                FC_LOG_MESSAGE( warn, "rethrow", FC_FORMAT_ARG_PARAMS( __VA_ARGS__) ), \
                std::current_exception() ); \
      wlog( "${details}", ("details",e.to_detail_string()) ); \
      wdump( __VA_ARGS__ ); \
      throw e; \
   }

#define FC_CAPTURE_AND_LOG( ... )  \
   catch( const boost::interprocess::bad_alloc& ) {\
      throw;\
   } catch( fc::exception& er ) { \
      wlog( "${details}", ("details",er.to_detail_string()) ); \
      wdump( __VA_ARGS__ ); \
   } catch( const std::exception& e ) {  \
      fc::exception fce( \
                FC_LOG_MESSAGE( warn, "rethrow ${what}: ",FC_FORMAT_ARG_PARAMS( __VA_ARGS__  )("what",e.what()) ), \
                fc::std_exception_code,\
                BOOST_CORE_TYPEID(e).name(), \
                e.what() ) ; \
      wlog( "${details}", ("details",fce.to_detail_string()) ); \
      wdump( __VA_ARGS__ ); \
   } catch( ... ) {  \
      fc::unhandled_exception e( \
                FC_LOG_MESSAGE( warn, "rethrow", FC_FORMAT_ARG_PARAMS( __VA_ARGS__) ), \
                std::current_exception() ); \
      wlog( "${details}", ("details",e.to_detail_string()) ); \
      wdump( __VA_ARGS__ ); \
   }

#define FC_LOG_AND_DROP( ... )  \
   catch( const boost::interprocess::bad_alloc& ) {\
      throw;\
   } catch( fc::exception& er ) { \
      wlog( "${details}", ("details",er.to_detail_string()) ); \
   } catch( const std::exception& e ) {  \
      fc::exception fce( \
                FC_LOG_MESSAGE( warn, "rethrow ${what}: ",FC_FORMAT_ARG_PARAMS( __VA_ARGS__  )("what",e.what()) ), \
                fc::std_exception_code,\
                BOOST_CORE_TYPEID(e).name(), \
                e.what() ) ; \
      wlog( "${details}", ("details",fce.to_detail_string()) ); \
   } catch( ... ) {  \
      fc::unhandled_exception e( \
                FC_LOG_MESSAGE( warn, "rethrow", FC_FORMAT_ARG_PARAMS( __VA_ARGS__) ), \
                std::current_exception() ); \
      wlog( "${details}", ("details",e.to_detail_string()) ); \
   }


/**
 *  @def FC_RETHROW_EXCEPTIONS(LOG_LEVEL,FORMAT,...)
 *  @brief  Catchs all exception's, std::exceptions, and ... and rethrows them after
 *   appending the provided log message.
 */
#define FC_RETHROW_EXCEPTIONS( LOG_LEVEL, FORMAT, ... ) \
   catch( const boost::interprocess::bad_alloc& ) {\
      throw;\
   } catch( fc::exception& er ) { \
      FC_RETHROW_EXCEPTION( er, LOG_LEVEL, FORMAT, __VA_ARGS__ ); \
   } catch( const std::exception& e ) {  \
      fc::exception fce( \
                FC_LOG_MESSAGE( LOG_LEVEL, "${what}: " FORMAT,__VA_ARGS__("what",e.what())), \
                fc::std_exception_code,\
                BOOST_CORE_TYPEID(e).name(), \
                e.what() ) ; throw fce;\
   } catch( ... ) {  \
      throw fc::unhandled_exception( \
                FC_LOG_MESSAGE( LOG_LEVEL, FORMAT,__VA_ARGS__), \
                std::current_exception() ); \
   }

#define FC_CAPTURE_AND_RETHROW( ... ) \
   catch( const boost::interprocess::bad_alloc& ) {\
      throw;\
   } catch( fc::exception& er ) { \
      FC_RETHROW_EXCEPTION( er, warn, "", FC_FORMAT_ARG_PARAMS(__VA_ARGS__) ); \
   } catch( const std::exception& e ) {  \
      fc::exception fce( \
                FC_LOG_MESSAGE( warn, "${what}: ",FC_FORMAT_ARG_PARAMS(__VA_ARGS__)("what",e.what())), \
                fc::std_exception_code,\
                BOOST_CORE_TYPEID(decltype(e)).name(), \
                e.what() ) ; throw fce;\
   } catch( ... ) {  \
      throw fc::unhandled_exception( \
                FC_LOG_MESSAGE( warn, "",FC_FORMAT_ARG_PARAMS(__VA_ARGS__)), \
                std::current_exception() ); \
   }

struct exception_api {
   void (*throw_exception)(int type, const char* fmt, ...);
};

