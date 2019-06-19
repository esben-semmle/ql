/**
 * Provides a taint-tracking configuration for reasoning about code injection.
 */

import javascript

module CodeInjection {

  /**
   * A taint-tracking configuration for reasoning about code injection vulnerabilities.
   */
  class Configuration extends TaintTracking::Configuration {
    Configuration() { this = "CodeInjection" }

    override predicate isSanitizer(DataFlow::Node node) {
      super.isSanitizer(node) or
      isSafeLocationProperty(node.asExpr())
    }

    override predicate isAdditionalTaintStep(DataFlow::Node src, DataFlow::Node trg) {
      // HTML sanitizers are insufficient protection against code injection
      src = trg.(HtmlSanitizerCall).getInput()
    }
  }
}
