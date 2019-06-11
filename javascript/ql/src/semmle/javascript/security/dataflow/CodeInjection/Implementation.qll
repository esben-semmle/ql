/**
 * Provides a default implementation of the interface for reasoning
 * about code injection.
 */

import javascript

module CodeInjection {
  import Interface::CodeInjection

  /** A source of remote user input, considered as a flow source for code injection. */
  class RemoteFlowSourceAsSource extends Source {
    RemoteFlowSourceAsSource() { this instanceof RemoteFlowSource }
  }

  /**
   * An access to a property that may hold (parts of) the document URL.
   */
  class LocationSource extends Source {
    LocationSource() { this = DOM::locationSource() }
  }

  /**
   * An expression which may be interpreted as an AngularJS expression.
   */
  class AngularJSExpressionSink extends Sink, DataFlow::ValueNode {
    AngularJSExpressionSink() {
      any(AngularJS::AngularJSCall call).interpretsArgumentAsCode(this.asExpr())
    }
  }

  /**
   * An expression which may be evaluated as JavaScript in NodeJS using the
   * `vm` module.
   */
  class NodeJSVmSink extends Sink, DataFlow::ValueNode {
    NodeJSVmSink() { exists(NodeJSLib::VmModuleMethodCall call | this = call.getACodeArgument()) }
  }

  /**
   * An expression which may be evaluated as JavaScript.
   */
  class EvalJavaScriptSink extends Sink, DataFlow::ValueNode {
    EvalJavaScriptSink() {
      exists(DataFlow::InvokeNode c, int index |
        exists(string callName | c = DataFlow::globalVarRef(callName).getAnInvocation() |
          callName = "eval" and index = 0
          or
          callName = "Function"
          or
          callName = "execScript" and index = 0
          or
          callName = "executeJavaScript" and index = 0
          or
          callName = "execCommand" and index = 0
          or
          callName = "setTimeout" and index = 0
          or
          callName = "setInterval" and index = 0
          or
          callName = "setImmediate" and index = 0
        )
        or
        exists(DataFlow::GlobalVarRefNode wasm, string methodName |
          wasm.getName() = "WebAssembly" and c = wasm.getAMemberCall(methodName)
        |
          methodName = "compile" or
          methodName = "compileStreaming"
        )
      |
        this = c.getArgument(index)
      )
    }
  }

  /**
   * An expression which is injected as JavaScript into a React Native `WebView`.
   */
  class WebViewInjectedJavaScriptSink extends Sink {
    WebViewInjectedJavaScriptSink() {
      exists(ReactNative::WebViewElement webView |
        // `injectedJavaScript` property of React Native `WebView`
        this = webView.getAPropertyWrite("injectedJavaScript").getRhs()
        or
        // argument to `injectJavascript` method of React Native `WebView`
        this = webView.getAMethodCall("injectJavaScript").getArgument(0)
      )
    }
  }
}
