import unittest

from autopentest.cli import build_parser


class CliTests(unittest.TestCase):
    def test_serve_command_defaults_to_8081(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["serve"])
        self.assertEqual(args.host, "127.0.0.1")
        self.assertEqual(args.port, 8081)


if __name__ == "__main__":
    unittest.main()
