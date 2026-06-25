using FluentValidation;
using FluentValidation.Results;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Extension methods that make it easier to run FluentValidation validators over collections
/// and dictionaries stored by the JSON-backed persistence layer.
/// </summary>
internal static class ValidatorExtensions
{
    /// <summary>
    /// Validates every item in a sequence and throws a single <see cref="ValidationException"/>
    /// containing all failures. Failure property names are prefixed with their zero-based index.
    /// </summary>
    public static void ValidateAllAndThrow<T>(this IValidator<T> validator, IEnumerable<T> items)
    {
        var failures = new List<ValidationFailure>();
        var index = 0;

        foreach (var item in items)
        {
            var result = validator.Validate(item);
            foreach (var failure in result.Errors)
            {
                failure.PropertyName = $"[{index}].{failure.PropertyName}";
                failures.Add(failure);
            }

            index++;
        }

        if (failures.Count > 0)
            throw new ValidationException(failures);
    }

    /// <summary>
    /// Validates each item and returns only the valid ones, counting the rejected ones.
    /// Never throws for validation failures — callers decide what to do with the rejected count.
    /// </summary>
    public static List<T> SelectValid<T>(this IValidator<T> validator, IEnumerable<T> items, out int rejectedCount)
    {
        var valid = validator.PartitionValid(items, out var rejected);
        rejectedCount = rejected.Count;
        return valid;
    }

    /// <summary>
    /// Validates each item and returns the valid ones while outputting the rejected ones.
    /// Never throws for validation failures.
    /// </summary>
    public static List<T> PartitionValid<T>(this IValidator<T> validator, IEnumerable<T> items, out List<T> rejectedItems)
    {
        var valid = new List<T>();
        var rejected = new List<T>();

        foreach (var item in items)
        {
            if (validator.Validate(item).IsValid)
                valid.Add(item);
            else
                rejected.Add(item);
        }

        rejectedItems = rejected;
        return valid;
    }

    /// <summary>
    /// Validates every value in a dictionary and throws a single <see cref="ValidationException"/>
    /// containing all failures. Failure property names are prefixed with their key.
    /// </summary>
    public static void ValidateAllAndThrow<TKey, TValue>(this IValidator<TValue> validator, IEnumerable<KeyValuePair<TKey, TValue>> items)
        where TKey : notnull
    {
        var failures = new List<ValidationFailure>();

        foreach (var kvp in items)
        {
            var result = validator.Validate(kvp.Value);
            foreach (var failure in result.Errors)
            {
                failure.PropertyName = $"[{kvp.Key}].{failure.PropertyName}";
                failures.Add(failure);
            }
        }

        if (failures.Count > 0)
            throw new ValidationException(failures);
    }

    /// <summary>
    /// Validates every value in a nested dictionary of dictionaries.
    /// </summary>
    public static void ValidateAllAndThrow<TOuterKey, TInnerKey, TValue>(
        this IValidator<TValue> validator,
        IEnumerable<KeyValuePair<TOuterKey, Dictionary<TInnerKey, TValue>>> items)
        where TOuterKey : notnull
        where TInnerKey : notnull
    {
        var failures = new List<ValidationFailure>();

        foreach (var outer in items)
        {
            foreach (var inner in outer.Value)
            {
                var result = validator.Validate(inner.Value);
                foreach (var failure in result.Errors)
                {
                    failure.PropertyName = $"[{outer.Key}][{inner.Key}].{failure.PropertyName}";
                    failures.Add(failure);
                }
            }
        }

        if (failures.Count > 0)
            throw new ValidationException(failures);
    }

    /// <summary>
    /// Rule helper that requires a <see cref="DateTime"/> to have <see cref="DateTimeKind.Utc"/>.
    /// </summary>
    public static IRuleBuilderOptions<T, DateTime> MustBeUtc<T>(this IRuleBuilder<T, DateTime> ruleBuilder)
    {
        return ruleBuilder.Must(d => d.Kind == DateTimeKind.Utc)
            .WithMessage("'{PropertyName}' must be UTC.");
    }

    /// <summary>
    /// Rule helper that requires a nullable <see cref="DateTime"/> to be UTC when it has a value.
    /// </summary>
    public static IRuleBuilderOptions<T, DateTime?> MustBeUtcWhenPresent<T>(this IRuleBuilder<T, DateTime?> ruleBuilder)
    {
        return ruleBuilder.Must(d => d == null || d.Value.Kind == DateTimeKind.Utc)
            .WithMessage("'{PropertyName}' must be UTC when present.");
    }

    /// <summary>
    /// Rule helper that requires a <see cref="DateTimeOffset"/> to be in UTC (offset zero).
    /// </summary>
    public static IRuleBuilderOptions<T, DateTimeOffset> MustBeUtc<T>(this IRuleBuilder<T, DateTimeOffset> ruleBuilder)
    {
        return ruleBuilder.Must(d => d.Offset == TimeSpan.Zero)
            .WithMessage("'{PropertyName}' must have a zero UTC offset.");
    }
}
