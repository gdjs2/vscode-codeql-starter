import cpp
import semmle.code.cpp.dataflow.TaintTracking

class MemoryDeallocator extends Expr {
	MemoryDeallocator() {
		this instanceof DeleteExpr or
		this instanceof DeleteArrayExpr or (
			this instanceof FunctionCall and 
			this.(FunctionCall).getTarget().hasGlobalName("free")
		)
	}

	Expr getOperand() {
		this instanceof DeleteExpr and result = this.(DeleteExpr).getExpr()
		or this instanceof DeleteArrayExpr and result = this.(DeleteArrayExpr).getExpr()
		or this instanceof FunctionCall and result = this.(FunctionCall).getArgument(0)
	}
}

class MemoryAllocator extends Expr {
	MemoryAllocator() {
		this instanceof NewExpr or 
		this instanceof NewArrayExpr or (
			this instanceof FunctionCall and
			this.(FunctionCall).getTarget().hasGlobalName("malloc")
		)
	}
}

class DerefExpr extends Expr {
	DerefExpr() {
		this instanceof PointerDereferenceExpr or
		this instanceof ArrayExpr
	}
	Expr getOperand() {
		this instanceof PointerDereferenceExpr and
			result = this.(PointerDereferenceExpr).getOperand()
		or this instanceof ArrayExpr and
			result = this.(ArrayExpr).getArrayBase()
	}
}

class UAFConfig extends TaintTracking::Configuration {
	UAFConfig() { this = "Use-After-Free Configuration" }
	override predicate isSource(DataFlow::Node node) {
		exists(Expr dealloc |
			dealloc instanceof MemoryDeallocator and 
			dealloc.(MemoryDeallocator).getOperand() = node.asExpr())
	}
	
	override predicate isSink(DataFlow::Node node) {
		exists(Expr deref |
			deref instanceof DerefExpr and 
			deref.(DerefExpr).getOperand() = node.asExpr())
	}
}

from UAFConfig cfg, DataFlow::PathNode node
where cfg.isSink(node.getNode())
select node, "is sink"

// from Expr e
// where e instanceof MemoryDeallocator
// select e.(MemoryDeallocator).getOperand()

// from Expr e
// where e instanceof DerefExpr
// select e.(DerefExpr).getOperand(), "is a memory dereference"