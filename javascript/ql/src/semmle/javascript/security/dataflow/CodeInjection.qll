/**
 * Provides a taint-tracking configuration for reasoning about code injection.
 */

import javascript

module CodeInjection {
  import CodeInjection.Nodes::CodeInjection
  private import CodeInjection.Configuration::CodeInjection as Base

  /**
   * A taint-tracking configuration for reasoning about code injection vulnerabilities.
   */
  class Configuration extends Base::Configuration {
    override predicate isSource(DataFlow::Node source) { source instanceof Source }

    override predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

    override predicate isSanitizer(DataFlow::Node node) {
      super.isSanitizer(node) or
      node instanceof Sanitizer
    }
  }
}
