<p align="center">
  <a href="https://logto.io" target="_blank" align="center" alt="Logto Logo">
    <picture>
      <source height="60" media="(prefers-color-scheme: dark)" srcset="https://github.com/logto-io/.github/raw/master/profile/logto-logo-dark.svg">
      <source height="60" media="(prefers-color-scheme: light)" srcset="https://github.com/logto-io/.github/raw/master/profile/logto-logo-light.svg">
      <img height="60" src="https://github.com/logto-io/logto/raw/master/logo.png" alt="Logto logo">
    </picture>
  </a>
  <br/><br/>
  <span><i><a href="https://logto.io" target="_blank">Logto</a> is an open-source Auth0 alternative designed for modern apps and SaaS products.</i></span>
</p>

# Logto Ruby on Rails sample

This is a sample Ruby on Rails project that demonstrates how to integrate Logto with your web application.

> [!Note]
> It used `rails new` to scaffold the project and then added the Logto Ruby SDK via path, which means you need to check out the whole repository to run this sample.

## Get started

1. Clone this repository
2. Install dependencies with `bundle install`
3. Create a `.env` file and add your Logto environment variables
4. Run the server with `bin/rails s`

### Environment variables

- `LOGTO_ENDPOINT`: Required. Your Logto tenant endpoint.
- `LOGTO_APP_ID`: Required. The "traditional web" application ID.
- `LOGTO_APP_SECRET`: Required. The "traditional web" application secret.

### Application settings

An "traditional web" application is required to run this sample. You can create one from the Logto Console.

Additionally, you need to add the following settings to your application (replace the port if you're using a different one):

- Redirect URI: `http://127.0.0.1:3000/callback` (or the host where your application is running)
- Post sign-out redirect URI: `http://127.0.0.1:3000/` (or the host where your application is running)

## Files to check

Rails has a complex structure, but the main files you need to check are:

- [app/controllers/sample_controller.rb](app/controllers/sample_controller.rb): The controller that handles the sample routes.
- [app/views/sample/index.html.erb](app/views/sample/index.html.erb): The view that renders the sample page.
- [config/routes.rb](config/routes.rb): The routes file that maps the sample routes to the controller.
- [config/application.rb](config/application.rb): The application file where the session store is configured.

### Persist the session

In this example, the session is stored in memory (see [config/application.rb](config/application.rb)) since the `:cookie_store` cannot store large amounts of data (>4KB). In production, you should use a different session store to persist the session.

## Can I change the place where the Logto Ruby SDK is initialized?

Yes. As a demonstration, the Logto Ruby SDK is initialized in the `sample_controller.rb` file. You can initialize it wherever you want, as long as it is done before you use it and has access to all the context it needs (e.g. environment variables, session, etc.).

## Resources

- [Documentation](https://docs.logto.io/quick-starts/ruby/)
- [Website](https://logto.io/)
- [Discord](https://discord.gg/vRvwuwgpVX)
