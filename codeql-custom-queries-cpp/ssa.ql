import cpp
import semmle.code.cpp.controlflow.SSA

from Variable var, Expr defExpr, Expr useExpr
where exists(SsaDefinition ssaDef |
	defExpr = ssaDef.getAnUltimateDefiningValue(var)
	and useExpr = ssaDef.getAUse(var))
select var, defExpr.getLocation().getStartLine() as dline, useExpr.getLocation().getStartLine() as uline