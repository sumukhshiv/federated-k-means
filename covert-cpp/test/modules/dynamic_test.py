# -*- Python -*-
# Dynamic test format for lit tests
import os
import sys

import lit
import lit.formats

class DynamicTest(lit.formats.ShTest):
    def __init__(self):
        # Choose between lit's internal shell pipeline runner and a real shell.  If
        # LIT_USE_INTERNAL_SHELL is in the environment, we use that as an override.
        use_lit_shell = os.environ.get("LIT_USE_INTERNAL_SHELL")
        if use_lit_shell:
            # 0 is external, "" is default, and everything else is internal.
            execute_external = (use_lit_shell == "0")
        else:
            # Otherwise we default to internal on Windows and external elsewhere, as
            # bash on Windows is usually very slow.
            execute_external = (not sys.platform in ['win32'])
        super(DynamicTest, self).__init__(execute_external)

    def execute(self, test, litConfig):
        saved_substitutions = list(test.config.substitutions)
        target_name = os.path.basename(test.getSourcePath())
        test.config.substitutions.append(('%basename', target_name))
        result = lit.TestRunner.executeShTest(test, litConfig, self.execute_external)
        test.config.substitutions = saved_substitutions
        return result
