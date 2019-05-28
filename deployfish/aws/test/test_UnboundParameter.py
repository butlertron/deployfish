import unittest
from mock import Mock, call

from testfixtures import compare, Replacer

from deployfish.aws.systems_manager import UnboundParameter


class TestUnboundParameter__render(unittest.TestCase):

    def test__render_read(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('foo.bar.BAZ')
            compare(p._render_read(), {'Names': ['foo.bar.BAZ'], 'WithDecryption': True})

    def test__render_write_no_encryption(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('foo.bar.BAZ')
            p.value = 'my_value'
            compare(
                p._render_write(),
                {
                    'Name': 'foo.bar.BAZ',
                    'Value': 'my_value',
                    'Overwrite': True,
                    'Type': 'String'
                }
            )

    def test__render_write_with_encryption(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('foo.bar.BAZ', kms_key_id="my_key")
            p.value = 'my_value'
            compare(
                p._render_write(),
                {
                    'Name': 'foo.bar.BAZ',
                    'Value': 'my_value',
                    'Overwrite': True,
                    'Type': 'SecureString',
                    'KeyId': 'my_key'
                }
            )


class TestUnboundParameter__is_secure(unittest.TestCase):

    def test__is_secure_no_key_no_aws_object_returns_False(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('foo.bar.BAZ')
            self.assertFalse(p.is_secure)

    def test__is_secure_key_but_no_aws_object_returns_True(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('foo.bar.BAZ', kms_key_id='my_key')
            self.assertTrue(p.is_secure)

    def test__is_secure_no_key_with_un_secure_aws_object_returns_False(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('foo.bar.BAZ')
            p._aws_parameter = {'Type': 'String'}
            self.assertFalse(p.is_secure)

    def test__is_secure_no_key_with_secure_aws_object_returns_True(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('foo.bar.BAZ')
            p._aws_parameter = {'Type': 'SecureString'}
            self.assertTrue(p.is_secure)

    def test__is_secure_with_key_with_secure_aws_object_returns_True(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('foo.bar.BAZ', kms_key_id='my_key')
            p._aws_parameter = {'Type': 'SecureString'}
            self.assertTrue(p.is_secure)


class TestUnboundParameter__prefix(unittest.TestCase):

    def test_get_prefix_returns_correct_prefix(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('foo.bar.BAZ')
            self.assertEqual(p.prefix, 'foo.bar.')

    def test_get_prefix_returns_empty_string_if_no_prefix(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('BAZ')
            self.assertEqual(p.prefix, '')

    def test_set_prefix_updates_prefix(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('BAZ')
            self.assertEqual(p.name, 'BAZ')
            self.assertEqual(p.prefix, '')
            p.prefix = 'foo.bar.'
            self.assertEqual(p.name, 'foo.bar.BAZ')
            self.assertEqual(p.prefix, 'foo.bar.')

    def test_set_prefix_accepts_empty_prefixes(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('foo.bar.BAZ')
            p.prefix = ''
            self.assertEqual(p.prefix, '')
            self.assertEqual(p.name, 'BAZ')

    def test_set_prefix_converts_None_to_empty_string(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('foo.bar.BAZ')
            p.prefix = None
            self.assertEqual(p.prefix, '')
            self.assertEqual(p.name, 'BAZ')

    def test_set_prefix_reloads_aws_object(self):
        from_aws = Mock()
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', from_aws)
            p = UnboundParameter('BAZ')
            p.prefix = 'foo.bar.'
            compare(from_aws.mock_calls, [call(), call()])


class TestUnboundParameter__name(unittest.TestCase):

    def test_get_name_returns_correct_name(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('foo.bar.BAZ')
            self.assertEqual(p.name, 'foo.bar.BAZ')

    def test_set_name_refuses_empty_names(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('BAZ')
            with self.assertRaises(ValueError):
                p.name = ''
            with self.assertRaises(ValueError):
                p.name = None

    def test_set_name_sets_name(self):
        from_aws = Mock()
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', from_aws)
            p = UnboundParameter('BAZ')
            p.name = 'foo.bar.BARNEY'
            self.assertEqual(p.name, 'foo.bar.BARNEY')

    def test_set_name_sets_key(self):
        from_aws = Mock()
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', from_aws)
            p = UnboundParameter('BAZ')
            p.name = 'foo.bar.BARNEY'
            self.assertEqual(p.key, 'BARNEY')

    def test_set_name_sets_prefix(self):
        from_aws = Mock()
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', from_aws)
            p = UnboundParameter('BAZ')
            p.name = 'foo.bar.BARNEY'
            self.assertEqual(p.prefix, 'foo.bar.')

    def test_set_name_reloads_aws_object(self):
        from_aws = Mock()
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', from_aws)
            p = UnboundParameter('BAZ')
            p.name = 'foo.bar.BARNEY'
            compare(from_aws.mock_calls, [call(), call()])


class TestUnboundParameter__key(unittest.TestCase):

    def test_get_key_returns_correct_key(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('foo.bar.BAZ')
            self.assertEqual(p.key, 'BAZ')

    def test_get_key_returns_correct_key_even_if_no_prefix(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('BAZ')
            self.assertEqual(p.key, 'BAZ')

    def test_set_key_refuses_empty_keys(self):
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', Mock())
            p = UnboundParameter('BAZ')
            with self.assertRaises(ValueError):
                p.key = ''
            with self.assertRaises(ValueError):
                p.key = None

    def test_set_key_sets_key(self):
        from_aws = Mock()
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', from_aws)
            p = UnboundParameter('BAZ')
            p.key = 'BARNEY'
            self.assertEqual(p.key, 'BARNEY')

    def test_set_key_sets_key_without_changing_prefix(self):
        from_aws = Mock()
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', from_aws)
            p = UnboundParameter('foo.bar.BAZ')
            p.key = 'BARNEY'
            self.assertEqual(p.key, 'BARNEY')
            self.assertEqual(p.prefix, 'foo.bar.')

    def test_set_key_reloads_aws_object(self):
        from_aws = Mock()
        with Replacer() as r:
            r.replace('deployfish.aws.systems_manager.UnboundParameter._from_aws', from_aws)
            p = UnboundParameter('BAZ')
            p.key = 'BARNEY'
            compare(from_aws.mock_calls, [call(), call()])
