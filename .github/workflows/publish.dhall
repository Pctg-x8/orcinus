let GHA =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/schema.dhall

let ProvidedSteps =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/ProvidedSteps.dhall

let PublishToken = GHA.mkExpression "secrets.PUBLISH_TOKEN"

let setupPythonStep =
      GHA.Step::{
      , name = "Setup python for tools"
      , uses = Some "actions/setup-python@v4"
      , `with` = Some
          (toMap { python-version = GHA.WithParameterType.Text "3.10" })
      }

let setupTomlReaderStep =
      GHA.Step::{
      , name = "Setup toml reader"
      , run = Some "pip install toml-cli"
      }

let installRustStep =
      GHA.Step::{
      , name = "Install Rust"
      , uses = Some "actions-rs/toolchain@v1"
      , `with` = Some
          (toMap { toolchain = GHA.WithParameterType.Text "stable" })
      }

let readVersionStep =
      GHA.Step::{
      , name = "Read release version"
      , id = Some "version"
      , run = Some
          "echo \"::set-output name=version::\$(toml get --toml-path ./Cargo.toml package.version)\""
      }

let publishStep =
      GHA.Step::{
      , name = "Publish to crates.io"
      , uses = Some "actions-rs/cargo@v1"
      , `with` = Some
          ( toMap
              { command = GHA.WithParameterType.Text "publish"
              , args = GHA.WithParameterType.Text "--token ${PublishToken}"
              }
          )
      }

in  GHA.Workflow::{
    , name = Some "Publish to crates.io"
    , on =
        GHA.On.Detailed
          GHA.OnDetails::{
          , push = Some GHA.OnPush::{ branches = Some [ "master" ] }
          }
    , jobs = toMap
        { publish = GHA.Job::{
          , runs-on = GHA.RunnerPlatform.ubuntu-latest
          , environment = Some "crates.io"
          , steps =
            [ ProvidedSteps.checkoutStep ProvidedSteps.CheckoutParams::{=}
            , installRustStep
            , setupPythonStep
            , setupTomlReaderStep
            , readVersionStep
            , publishStep
            , ProvidedSteps.createReleaseStep
                ProvidedSteps.CreateReleaseParams::{
                , tag_name = GHA.mkExpression "steps.version.outputs.version"
                , release_name =
                    GHA.mkExpression "steps.version.outputs.version"
                , body = ProvidedSteps.CreateReleaseBody.Text ""
                , draft = Some False
                , prerelease = Some False
                }
            ]
          }
        }
    }
