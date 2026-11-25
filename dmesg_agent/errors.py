"""公共异常,避免 collectors 与 executors 循环导入。"""


class CollectError(Exception):
    pass
