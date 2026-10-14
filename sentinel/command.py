"""Installed standalone entry point, reusing the existing Sentinel command group."""


def main():
    from cli import sentinel_app
    sentinel_app(prog_name='sentinel')


if __name__ == '__main__':
    main()
