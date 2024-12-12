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
            "IsFirstSignIn": True #flag for first time sign-in setup
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
    logging.info("Processing sign-in request.")

    try:
        req_body = req.get_json()
        username = req_body.get("username")
        password = req_body.get("password")

        if not username or not password:
            return func.HttpResponse("Missing required fields.", status_code=400)

        # Simulate checking user in the database
        user_exists = True  # Example; replace with actual DB check

        if user_exists:
            # Simulate checking if it's the user's first time logging in
            is_first_sign_in = True  # Example; replace with actual check

            if is_first_sign_in:
                # If it's the first sign-in, return the redirect response
                return func.HttpResponse(
                    '{"redirect": "/setup.html"}',
                    status_code=200,
                    mimetype="application/json"
                )
            else:
                # If not first sign-in, return a success message
                return func.HttpResponse(
                    '{"message": "Sign-in successful!"}',
                    status_code=200,
                    mimetype="application/json"
                )

        else:
            return func.HttpResponse("User not found.", status_code=404)

    except Exception as e:
        logging.error(f"Error during sign-in: {e}")
        return func.HttpResponse(
            f'{{"message": "An error occurred: {str(e)}"}}',
            status_code=500,
            mimetype="application/json"
        )


@app.route(route="CompleteSetupFunction", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def complete_setup(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing setup completion request.")

    try:
        # Parse the incoming JSON body
        req_body = req.get_json()
        username = req_body.get("username")
        name = req_body.get("name")
        email = req_body.get("email")

        if not username or not name or not email:
            return func.HttpResponse("Missing required fields.", status_code=400)

        logging.info(f"Received setup completion for username: {username}")

        # Connect to Azure Table Storage
        table_service_client = TableServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
        table_client = table_service_client.get_table_client(TABLE_NAME)

        # Prepare the user entity data to be inserted or updated
        user_entity = {
            "PartitionKey": "Users",  # Partition key (all users will be in this partition)
            "RowKey": username,  # Row key (unique identifier for the user)
            "Name": name,  # Store the name
            "Email": email,  # Store the email
            "IsFirstSignIn": False  # Mark that the user has completed the setup
        }

        # Insert or update the user entity
        try:
            # This will insert the entity if it does not exist or update it if it already exists
            table_client.upsert_entity(user_entity)
            logging.info(f"User setup successfully completed for {username}.")
        except Exception as e:
            logging.error(f"Error saving user entity: {e}")
            return func.HttpResponse(
                f'{{"message": "An error occurred while saving user data: {str(e)}"}}',
                status_code=500,
                mimetype="application/json"
            )

        # Return a successful response after completion
        return func.HttpResponse(
            '{"message": "Setup completed successfully!"}',
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error during setup completion: {e}")
        return func.HttpResponse(
            f'{{"message": "An error occurred: {str(e)}"}}',
            status_code=500,
            mimetype="application/json"
        )