import os
import yara
from slacksecrets.secrets import build_rules_filepaths

DEFAULT_EXTERNALS = {"filename": ""}


def pytest_generate_tests(metafunc):
    required_meta_tags = ['name', 'author', 'date']
    idlist = []
    argnames = ["rule", "required_meta_tag"]
    argvalues = []
    for rule_name, path in metafunc.cls.yara_files.items():
        rules = yara.compile(filepaths={rule_name: path}, externals=DEFAULT_EXTERNALS)
        if len(list(rules)) == 0:
            continue
        for rule in rules:
            for required_meta_tag in required_meta_tags:
                idlist.append("{} Meta '{}' Tag Exist".format(rule.identifier, required_meta_tag))
                argvalues.append([rule, required_meta_tag])

    metafunc.parametrize(argnames, argvalues, ids=idlist, scope="class")


class TestYaraFormat:
    yara_files = build_rules_filepaths([os.path.join('..', 'slacksecrets', 'rules')])

    def test_yara_rule(self, rule, required_meta_tag):
        assert (required_meta_tag in rule.meta.keys())
