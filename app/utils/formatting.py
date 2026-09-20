def format_currency(amount):
    return f"Rs. {amount:,.2f}"


def generate_fast_title(first_prompt):
    return (first_prompt[:30] + "...") if len(first_prompt) > 30 else first_prompt
