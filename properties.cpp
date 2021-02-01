//=============================================================================
// Copyright (c) 2015-2018 glywk
// https://github.com/glywk
// 
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//=============================================================================

#include <iostream>
#include <vector>
#include <functional>

#include "properties.h"

#include "sample/action/properties_action.hpp"

namespace lex = boost::spirit::lex;
namespace cp = cpp_properties;
using namespace cp::token;

#define CALL_MEMBER_FN(member_function)  ((*this).*(member_function))

/*!
 * the key-value property traits to provide to visit the abstract syntax tree.
 */
struct properties_actor_traits {
    typedef std::vector <std::pair<std::string, std::string>> properties_type;
    typedef properties_type::value_type property_type;
};

/*!
 * Collects all key-value properties in the analyzed input sequence by
 * identifying the matched tokens as passed from the lexer.
 */
template<typename Traits>
class properties_actor {
public:
    // type of properties container output
    typedef typename Traits::properties_type properties_type;
    // type of a key-value property
    typedef typename Traits::property_type property_type;

    properties_actor(properties_type &properties_reference) :
        properties(properties_reference),
        property(none),
        current_reference(&properties_actor::allocate) {}

    /*!
     * store the current property and change state to prepare
     * the next property read.
     */
    void push_back() {
        current_reference = &properties_actor::allocate;
    }

    /*!
     * create the current property pair to populate and change state to
     * return the current reference.
     */
    property_type &current() {
        return CALL_MEMBER_FN(current_reference)();
    }

private:
    property_type &get() {
        return property;
    };

    property_type &allocate() {
        current_reference = &properties_actor::get;
        properties.emplace_back(std::string(), std::string());
        property = properties.back();
        return property;
    };

    // the property container to populate
    properties_type &properties;

    // default reference
    property_type none;

    // the temporary property
    std::reference_wrapper <property_type> property;

    // callback for lazy initialization of current property pair 
    typedef property_type &(properties_actor::*current_reference_callback)();

    // the callback to retrieve the current property reference
    current_reference_callback current_reference;
};

/*!
 * tokenize the text and populate the output container
 */
template<
    typename Traits,
    typename Actor = properties_actor<Traits>,
    typename Action = properties_action <Actor>
>
static bool tokenize_and_parse(char const *first, char const *last, typename Traits::properties_type &cpp_properties) {
    // create the token definition instance needed to invoke the lexical analyzer
    cp::cpp_properties_lexer <lex::lexertl::lexer<>> lexer;

    Actor actor(cpp_properties);
    Action action = std::move(make_action(actor));

    return lex::tokenize(first, last, lexer, [&action](auto token) {
        return action(token);
    });
}

/**
 * Read the given field from the .properties file, or return an empty string if the property wasn't found.
 * 
 * @param propFile 
 * @param fieldName 
 * @return 
 */
std::string propertiesReadField(const std::string &propertiesFile, const std::string fieldName) {
    char const *first = propertiesFile.data();
    char const *last = first + propertiesFile.size();

    properties_actor_traits::properties_type cpp_properties;

    bool success = tokenize_and_parse<properties_actor_traits>(first, last, cpp_properties);

    if (!success) {
        throw std::runtime_error("Failed to parse properties file");
    }

    for (auto p : cpp_properties) {
        if (p.first == fieldName) {
            return p.second;
        }
    }
    
    return "";
}