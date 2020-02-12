import ast
import os

import pkg_resources
import yara

from slacksecrets.secrets import build_rules_filepaths

DEFAULT_EXTERNALS = {"filename": ""}


def pytest_generate_tests(metafunc):
    ids = []
    arg_names = ["test_type", "rules", "test_case", "test_externals"]
    arg_values = []
    for rule_name, path in metafunc.cls.yara_files.items():
        rules = yara.compile(filepaths={rule_name: path}, externals=DEFAULT_EXTERNALS)
        if len(list(rules)) == 0:
            continue
        rules_in_file = 0
        for rule in rules:
            i = 1
            rules_in_file += 1
            for k in rule.meta.keys():
                if k.endswith("_externals"):
                    # The external vars will be processed with the associated test cases
                    continue

                if k.startswith("test_match") or k.startswith("test_no_match"):
                    externals_key = "{}_externals".format(k)
                    ids.append("{}::{}".format(rule.identifier, k))
                    arg_values.append([
                        "match" if k.startswith("test_match") else "no_match",
                        rules,
                        rule.meta.get(k),

                        # Valid JSON has key/values enclosed in double-quotes;
                        # YARA strings are declared with double-quotes.
                        #
                        # To avoid adding tons of escape backslashes,
                        # have the YARA rules use single-quotes for keys/values,
                        # and then use Python's safe AST.literal_eval function to parse the string as a dict:
                        # https://docs.python.org/3/library/ast.html#ast.literal_eval
                        #
                        # This is only used in test code and not in the package code,
                        # so the performance hit won't matter, and security concerns should be mitigated
                        ast.literal_eval(
                            rule.meta.get(externals_key)) if externals_key in rule.meta.keys() else DEFAULT_EXTERNALS
                    ])
                    i += 1

            # All YARA rule files should only have a single rule
            ids.append("{} 1 Rule Per File".format(rule.identifier))
            arg_values.append(["rule_count", rules, rules_in_file, DEFAULT_EXTERNALS])

            # Force test-cases for all YARA rules
            # We start i at 1 for naming convenience, so it'll be incremented to 2 after the first test is found
            if i == 1:
                ids.append("{} Tests Exist".format(rule.identifier))
                arg_values.append(["rules_exist", rules, i - 1, DEFAULT_EXTERNALS])

    metafunc.parametrize(arg_names, arg_values, ids=ids, scope="class")


class TestYaraScenarios:
    yara_files = build_rules_filepaths([pkg_resources.resource_filename('slacksecrets', 'rules')])

    def test_yara_rule(self, test_type, rules, test_case, test_externals):
        if test_type.startswith("rules_exist"):
            assert (int(test_case) > 0)
        elif test_type.startswith("rule_count"):
            assert (int(test_case) == 1)
        elif test_type in ["match", "no_match"]:
            matches = rules.match(data=test_case, externals=test_externals)
            assert (test_type == "match" and (len(matches) > 0)) or \
                   (test_type == "no_match" and (len(matches) == 0))
