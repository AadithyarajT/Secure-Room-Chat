# # chat/redis_client.py
# import redis
# from django.conf import settings

# # Create a connection pool (reuse connections)
# redis_pool = redis.ConnectionPool(
#     host=getattr(settings, "REDIS_HOST", "localhost"),
#     port=getattr(settings, "REDIS_PORT", 6379),
#     db=0,
#     decode_responses=True,
#     max_connections=50,  # Adjust based on your needs
# )


# def get_redis_client():
#     """Get a Redis client from the connection pool"""
#     return redis.Redis(connection_pool=redis_pool)


