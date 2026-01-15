from ratelimit.decorators import ratelimit

# Example:
# Limit access attempts: 5 requests per minute per IP
attempt_limit = ratelimit(key='ip', rate='5/m', block=True)
