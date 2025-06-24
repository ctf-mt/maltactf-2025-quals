using System;
using System.IO;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Antiforgery;
using NVelocity;
using NVelocity.App;
using NVelocity.Runtime;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAntiforgery();
var app = builder.Build();
app.UseAntiforgery();

app.MapGet("/", async (HttpContext context, IAntiforgery antiforgery) =>
{
    var csrfToken = antiforgery.GetAndStoreTokens(context);
    
    context.Response.ContentType = "text/html; charset=utf-8";
    await context.Response.WriteAsync($@"
        <html>
        <head>
            <title>Enterprise Template as a Service</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; line-height: 1.6; padding: 2rem; max-width: 800px; margin: auto; }}
                button {{ font-size: 1rem; padding: 0.5rem 1rem; border-radius: 5px; border: 0; background-color: #007aff; color: white; cursor: pointer; }}
                pre {{ background-color: #f0f0f0; border: 1px solid #ccc; padding: 1rem; border-radius: 5px; }}
                form {{ display: flex; flex-direction: column; gap: 1.25rem; max-width: 450px; }}
                form div {{ display: flex; flex-direction: column; }}
                label {{ font-weight: 500; margin-bottom: 0.25rem; }}
                input[type='text'], select {{ font-family: inherit; font-size: 1rem; padding: 0.75rem; border-radius: 5px; border: 1px solid #ccc; background-color: white; -webkit-appearance: none; -moz-appearance: none; appearance: none; width: 100%; transition: border-color 0.2s, box-shadow 0.2s; }}
                select {{ background-image: url(""data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' fill='currentColor' viewBox='0 0 16 16'%3E%3Cpath fill-rule='evenodd' d='M1.646 4.646a.5.5 0 0 1 .708 0L8 10.293l5.646-5.647a.5.5 0 0 1 .708.708l-6 6a.5.5 0 0 1-.708 0l-6-6a.5.5 0 0 1 0-.708z'/%3E%3C/svg%3E""); background-repeat: no-repeat; background-position: right 0.75rem center; background-size: 1em; }}
                input[type='text']:hover, select:hover {{ border-color: #999; }}
                input[type='text']:focus, select:focus {{ outline: none; border-color: #007aff; box-shadow: 0 0 0 3px rgba(0, 122, 255, 0.25); }}
                fieldset {{ padding: 0; display: flex; flex-direction: column; gap: 1rem; border: 1px solid #ddd; border-radius: 5px; padding: 1.25rem; }}
                legend {{ font-weight: 500; font-size: 0.9rem; color: #555; padding: 0 0.5rem; }}
            </style>
        </head>
        <body>
            <h1>Enterprise Template as a Service</h1>
            <p>
                Test out our enterprise&trade; template renderer! We've created a collection of 3 templates you can use freely to test our product!
            </p>

            <form action='/' method='post'>
                <input name='{csrfToken.FormFieldName}' type='hidden' value='{csrfToken.RequestToken}'>
                <div>
                    <label for='template-select'>Template</label>
                    <select name='template' id='template-select'>
                        <option value='greeting.tmpl'>Greeting</option>
                        <option value='verify_email.tmpl'>Verify Email</option>
                        <option value='current_date.tmpl'>Current Date</option>
                    </select>
                </div>

                <fieldset>
                    <legend>Variables</legend>
                    
                    <div>
                        <label for='name-input'>Name</label>
                        <input type='text' name='name' id='name-input' value='John Lua'>
                    </div>
                    
                    <div>
                        <label for='url-input'>URL</label>
                        <input type='text' name='url' id='url-input' value='https://example.com'>
                    </div>
                </fieldset>

                <button type='submit'>Render Template</button>
            </form>
        </body>
        </html>");
});

app.MapPost("/", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    string templateName = form["template"];
    if (string.IsNullOrEmpty(templateName))
    {
        await context.Response.WriteAsync("missing template field");
        return;
    }

    var templatePath = Path.Combine("templates", templateName);

    VelocityEngine velocity = new VelocityEngine();
    velocity.Init();

    VelocityContext velocityContext = new VelocityContext();
    velocityContext.Put("name", System.Net.WebUtility.HtmlEncode(form["name"].ToString()));
    velocityContext.Put("url", System.Net.WebUtility.HtmlEncode(form["url"].ToString()));
    velocityContext.Put("date", System.Net.WebUtility.HtmlEncode(DateTime.Now.ToString()));

    var writer = new StringWriter();
    try {
        var template = await File.ReadAllTextAsync(templatePath);
        Boolean ok = velocity.Evaluate(velocityContext, writer, templateName, template);
    } catch (Exception e) {
        await context.Response.WriteAsync("template rendering failed");
        return;
    }


    context.Response.ContentType = "text/html; charset=utf-8";
    await context.Response.WriteAsync(writer.ToString());
});

app.Run();