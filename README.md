# java-oauth2

java-oauth2 initial should be the same as java-usermodel - expections and logging

### server.port
* Default port 8080, otherwise defined in resources/application.properties.

### Logging
* Under Spring boot, slf4j and LogBack are treated the same. 
* Include slf4j as dependency in pom.xml, a file logback-spring.xml can be created to control loggging output to files and console.
* slf4j enables LoggerFactory to creater logger.info.In application.properties -> server.port=${PORT:2019}

### In eclipse Project Explorer,
* If spring boot starter web is managed by maven in pom.xml, tomcat will be managed by Spring boot.
* right click the project name -> select "Run As" -> "Maven Build..."
* In the goals, enter _> spring-boot:run
* then click Run button


* If tomcat is installed in pom.xml
* goals -> tomcat:run

## Oauth2 - default in the Spring Security module

> OAuth2 is an industry standard protocol for user authentication. User authentication is the verification of what human is accessing our system. Client applications request an access token from a backend API system. Gaining an access token allows a user to access projected resources, endpoints and allows the backend system to know who that user is without the user having to provide their username and password for each transaction. Gaining this access token is done through a two step process.

* Clients must be authorized to access the system using a client user name and password, called a client id and client secret in the OAuth2 protocol. This client id and client secret could be the same for all clients who want to access the backend API, or each client could receive their own id and secret. The ids and secrets are controlled by the backend system. The backend system must tell the client what client id and client secret to use!
   - Sometimes a client will send an authorization token instead of a client id and client secret. For our purposes, this authorization token is simply the client id and client secret combined and encoded using Base64 encoding.
* After a client has been authorized, an individual user is authenticated to the system using a user name and password.

> These two steps are necessary but are usually combined into a single request from the client for an access token. After initially getting the access token, the client must send that token with each subsequent request. The access token can be used by the backend system to determine what user is accessing the system.

In the OAuth2 framework, 4 Roles are identified.

* The client
   - Often called the frontend. This is the application that wishes to access our backend API server.
* The Resource Server
   - This is our backend API server. It is the server that hosts the protected information.
* The Authorization Server
   - This is the part of the backend application that grants access tokens. Access tokens are only granted after the client is authorized and the user is authenticated. When we think of using Google, Facebook, GitHub to logon to a system, what we mean is that we are using their authorization server to get an access token. 
* The Resource Owner
   - Usually a person that grant access to a protected resource. Think something like a system admin.
   
### Roles in our code
> We will be using Spring Security to implement OAuth2. OAuth2 is the default, standard protocol implemented by Spring Security. That will make implementation easier. The implement is a series of boilerplate code that is customized to fit our applications. We will be using

* An AuthorizationServerConfig class that will serve the role of the Authorization Server. We use the @EnableAuthorizationServer annotation to set up a default authorization server and then customize it to fit our applications.
* A ResourceServerConfig class that will serve the role of the resource server. We use the @EnableResourceServer annotation to set up a default resource server and then customize it to fit our application. Most of our application is concerned with how to protect, display, and manipulate resources. So most of our application, including all that we have coded up until this point, can be considered part of the resource server.
* A SecurityConfig class that will serve as the main configuration class for our OAuth2 server. We use the @EnableWebSecurity annotation to say, yes we want to use web security and then we configure this web security to our own needs.

> Do note that the OAuth2 process as authorization or authentication. This is not correct. Those are two different parts of the OAuth2 protocol. However, in the industry often the OAuth2 protocol is referred to as authorization or authentication.

### Gaining Access
> In order to request an access token, our client needs to know the client id and client secret. These will be provided to the client by the backend administrator. It is OUR responsibility to give the frontend the client id and client secret. The frontend client does not get to choose what these are, we do. Commonly you will see these being hard to guess random characters, normally 32 character hex strings. Sometimes you will see the client id and client security provided as Base64 API access tokens. A client would use either the client id / client security combination or the API access token to get authorized to the system. They do NOT use both. Which one they use is often left to the client to decide. The format of combining the client id and client secret is to take the following and encode it using Base64:

* client id:client secret

* Client id: 6779ef20e75817d76902 Client security: 9e51c1701e1a6f5cfb30780d94d38b8d API access token: Njc3OWVmMjBlNzU4MTdkNzY5MDI6OWU1MWMxNzAxZTFhNmY1Y2ZiMzA3ODBkOTRkMzhiOGQ=


> For our purposes we will use something easy to read. This will make reviewing each other’s code much easier.

* Client id: lambda-client Client security: lambda-secret API access token: bGFtYmRhLWNsaWVudDpsYW1iZGEtc2VjcmV0


### Adding a new user
> But before we can request access to the system, we need a user set up, you know, the one requesting access!

> Adding a new user is the same as adding any other record to our database. The one additional item is that the password has to be encrypted. Although not required, encrypting the password is definitely the preferred practice! We use an encryption algorithm called BCrypt. This is fairly standard in the industry.

> We say which algorithm we are going to use in the SecurityConfig class. This is where we setup the Bean for PasswordEncoder in SecurityConfig class.
![SecurityConfig Encoder](./SecurityConf_Encoder.png)

![User Setpassword](./User_Setpasswd.png)

### Authorizing the client
> The step in using the API Backend is to Authorize the client, the application wanting to use the API. The client has a special username and password needed to access the backend. They also have special names.

* username => client id
* password => client secret

> These are sent to the API backend via the Authorization header in a REST API request. They can either be sent as a username and password, or as is more common an API Key. The API Key is simply the string client id:client secret encoded using Base64.

> The AuthorizationServerConfig class is responsible for handling the Authorization of the client.

* In our case we list the client id and client secret directly in the AuthorizationServerConfig allowing for only one client id, client secret combination. Some systems provide access to multiple client ids but that is a more advanced topic.
* Note that the client secret is also encrypted using BCrypt, using our encode Bean from the SecurityConfig class.
* Other configurations happen in the AuthorizationServerConfig like how long a token is valid.

![AuthorizationServerConfig secret access](./AuthServConfig.png)

* We also set what the login endpoint from where a user, not to be confused with the client, gets their authentication token.
    - Client is the fontend system accessing the API Backend
    - User is the person, usually, actually handling data from the Backend.
    
 ![AuthorizationServerConfig endpoint](./AuthServConf_endpt.png)
 
### Authenticating the user
> In most REST API calls from a client, the Authorization and Authentication are handled in a single request. The client just sends the client id and client secret along with a username and password to the API Backend System. That API Backend System takes care of Authorizing the client and then Authenticated the user!

> Authenticating a user happens after the client is Authorized. The client must have access to the API Backend System via its client id and client secret before it can request an Authentication token for a user.

> The process of Authentication is taking a username and password and determining if that combination is a valid combination, represents a valid user, of the system. If the validity of the user is confirmed, the API Backend System returns to the client an Authentication Token. It is this token that will identify the user in future requests.

> That Authentication Token is store in the Token Store. You can think of a Token Store as a table in memory with columns contains data such as

* The Authentication Token
* The time the token is to expire
* The Authentication object of the user, the UserDetails Security Object which is essentially a cached copy of the user record only containing data necessary for security.
* The Token Store Bean is set up in the SecurityConfig class and configured as the Authentication Manager in the AuthorizationServerConfig

![SecurityConfig token](./SecurityConf_TokenStore.png)

![AuthServConfig authentication](./AuthServConf_AuthenticationManager.png)

### Using the authentication token
> Note that we restrict what user can do what with our data through user roles. Users get access to read, manipulate certain pieces of data by what role they are assigned. Role assignment are often done by type of user: admin, dataentry, user. Sometimes departments are added: systemadim, accountingadmin, hrdataentry, manufacturinguser. The name of the role can be anything but is usually something that makes sense to a human reading the role title. Role titles do get hard coded in our applications when we are restricting data to certain roles. So name roles carefully as changing the name of role is a BIG deal!

> Now we have an authentication token that identifies that this is a valid user and identifies which user it is. From this authentication token we can also identify what can access.

> To access a restricted endpoint, the client send an authentication token in the Authorization header.

> Spring Framework looks for that authentication token in the TokenStore

* If Spring Security finds the token in the TokenStore
    - Spring Security sees if the user associated with this token has access to the requested endpoint.
       - This is handled through the getAuthority method in the User model
       - This method returns which “Authorities” the user has been granted. In our case, those authorities are equivalent to our roles.

![User getAuthority](./User_GetAuthority.png)

* If Spring Security does not find the token in the TokenStore, an unauthorized status is returned.

* To determine which roles has access to what endpoints, the first place to check is the ResourceServerConfig. This class determines which roles have access to which resources, or endpoints. The majority of your security configuration happens in this class.

![ResourceServerConfig endpoint](./ResourceServerConfig_endpt.png)

* You allow access to a resource using .antMatchers
* The parameter for .antMatcher is a regular expression stating which endpoints you want to restrict.
* The .antMatchers ends with a method
    - .permitAll() - allows access to all. No Authentication Token is necessary
    - .authenticated() - allows access to all authenticated users. A valid authentication token is required.
    - .hasAnyRole() - the parameter is a list of roles who have access to these endpoints.
* You can further restrict your security access using a @PreAuthorize annotation in the Controller. This further restrict access to this endpoint to only the given roles. Note: you cannot expand access via this method only further restrict it.

![UserController PreAuthorization](./UserController_PreAuthorization.png)


