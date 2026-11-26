"""Shared exception, avoiding a circular import between collectors and executors."""


class CollectError(Exception):
    pass
