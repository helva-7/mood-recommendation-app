import azure.functions as func
import logging
from azure.data.tables import TableServiceClient
import bcrypt

# Create a FunctionApp instance
app = func.FunctionApp()

# Local Azurite connection string
STORAGE_CONNECTION_STRING = "UseDevelopmentStorage=true"
TABLE_NAME = "Users"

@app.route(route="AuthFunction", methods=["POST"] ,auth_level=func.AuthLevel.ANONYMOUS)
def register_user(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing a request for user registration")

    try: 
        req_body = req.get_json()
        logging.info(f"Received request body: {req_body}")
        username = req_body.get("username")
        password = req_body.get("password")
    except ValueError:
        logging.error("Failed to parse request body as JSON")
        return func.HttpResponse("Invalid input", status_code=400)
    
    if not username or not password:
        return func.HttpResponse("Username and password required.", status_code=400)
    
    try:
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # Connect to Azurite Table Storage
        table_service_client = TableServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
        table_client = table_service_client.get_table_client(TABLE_NAME)

        try:
            table_client.create_table()
        except Exception as e:
            logging.info(f"Table might exist: {e}")
        try:
            existing_user = table_client.get_entity(partition_key="Users", row_key=username)
            if existing_user:
                logging.info(f"Username {username} already exists.")
                return func.HttpResponse(
                    '{"message": "Username already exists."}',
                    status_code=409,
                    mimetype="application/json"
                )
        except Exception as e:
            # EntityNotFoundError is expected if the username doesn't exist
            logging.info(f"Username {username} not found, proceeding with registration.")

        entity = {
            "PartitionKey": "Users",
            "RowKey": username,
            "Password": hashed_password.decode("utf-8"),
        }

        table_client.create_entity(entity)

        return func.HttpResponse(
            '{"message": "User registered successfully!", "redirect": "/signin.html"}',
            status_code=201,
            mimetype="application/json"
        )
    
    except Exception as e:
        logging.error(f"Error during registration: {e}")
        return func.HttpResponse("An error occurred while registering the user", status_code=500)

@app.route(route="SignInFunction", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def sign_in_user(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing a request for user sign-in")

    try:
        req_body = req.get_json()
        logging.info(f"Received request body: {req_body}")
        username = req_body.get("username")
        password = req_body.get("password")
    except ValueError:
        return func.HttpResponse("Invalid input", status_code=400)

    if not username or not password:
        return func.HttpResponse("Username and password required.", status_code=400)

    try:
        # Connect to Azurite Table Storage
        table_service_client = TableServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
        table_client = table_service_client.get_table_client(TABLE_NAME)

        # Check if the user exists
        try:
            user_entity = table_client.get_entity(partition_key="Users", row_key=username)

            # Verify the password
            stored_password = user_entity["Password"]
            if bcrypt.checkpw(password.encode("utf-8"), stored_password.encode("utf-8")):
                # Redirect to the homepage
                return func.HttpResponse(
                    '{"message": "Sign-in successful!", "redirect_url": "/homepage"}',
                    status_code=200,
                    mimetype="application/json"
                )
            else:
                return func.HttpResponse(
                    '{"message": "Invalid username or password."}',
                    status_code=401,
                    mimetype="application/json"
                )
        except Exception:
            return func.HttpResponse(
                '{"message": "Invalid username or password."}',
                status_code=401,
                mimetype="application/json"
            )

    except Exception as e:
        logging.error(f"Error during sign-in: {e}")
        return func.HttpResponse(
            '{"message": "An error occurred while signing in."}',
            status_code=500,
            mimetype="application/json"
        )
