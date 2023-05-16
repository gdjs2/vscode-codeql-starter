/**
 * @name Empty block
 * @kind problem
 * @problem.severity warning
 * @id cpp/example/empty-block
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

class FunctionFCall extends Expr {
  FunctionFCall() {
    exists(FunctionCall fc, Function f | 
      fc.getTarget() = f and 
      f.getName() = "f" and 
      this = fc)
  }
}

class FunctionVulCall extends Expr {
  FunctionVulCall() {
    exists(FunctionCall fc, Function f | 
      fc.getTarget() = f and
      f.getName() = "vul" and
      this = fc)
  }
}

class F2VulConfig extends TaintTracking::Configuration {
  F2VulConfig() { this = "F2VulConfig" }
  override predicate isSource(DataFlow::Node node) {
    node.asExpr() instanceof FunctionFCall
  }
  
  override predicate isSink(DataFlow::Node node) {
    exists(FunctionCall fc | 
      fc.getTarget().getName() = "vul" and
      node.asExpr() = fc.getArgument([0 .. fc.getNumberOfArguments()]))
  }
}

from F2VulConfig cfg, DataFlow::PathNode src, DataFlow::PathNode sink
where cfg.hasFlowPath(src, sink)
select "from", sink, "to", src