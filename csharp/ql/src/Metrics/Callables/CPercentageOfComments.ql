/**
 * @name Comment ratio per function
 * @description Methods where a small percentage of the lines are commented might not have sufficient documentation to make them understandable.
 * @kind treemap
 * @treemap.warnOn lowValues
 * @metricType callable
 * @metricAggregate avg max
 * @tags maintainability
 *       documentation
 * @deprecated
 */
import csharp

from Callable f, int loc
where f.isSourceDeclaration() and loc = f.getNumberOfLines() and loc > 0
select f, 100.0 * ((float)f.getNumberOfLinesOfComments() / (float)loc)
