let GHA =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/schema.dhall

let checkout =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/ProvidedSteps/actions/checkout.dhall

let createRelease =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/ProvidedSteps/actions/create-release.dhall

let setupPython =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/ProvidedSteps/actions/setup-python.dhall

let setupRust =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/ProvidedSteps/actions-rs/toolchain.dhall

let runCargo =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/ProvidedSteps/actions-rs/cargo.dhall

let PublishToken = GHA.mkExpression "secrets.PUBLISH_TOKEN"

let setupTomlReaderStep =
      GHA.Step::{
      , name = "Setup toml reader"
      , run = Some "pip install toml-cli"
      }

let readVersionStep =
      GHA.Step::{
      , name = "Read release version"
      , id = Some "version"
      , run = Some
          "echo \"::set-output name=version::\$(toml get --toml-path ./Cargo.toml package.version)\""
      }

let publishStep =
      runCargo.step
        runCargo.Params::{
        , command = "publish"
        , args = Some "--token ${PublishToken}"
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
            [ checkout.step checkout.Params::{=}
            , setupRust.step setupRust.Params::{ toolchain = Some "stable" }
            , setupPython.step
                setupPython.Params::{ python-version = Some "3.10" }
            , setupTomlReaderStep
            , readVersionStep
            , publishStep
            , createRelease.step
                createRelease.Params::{
                , tag_name = GHA.mkRefStepOutputExpression "version" "version"
                , release_name =
                    GHA.mkRefStepOutputExpression "version" "version"
                , body = createRelease.Body.Text ""
                , draft = Some False
                , prerelease = Some False
                }
            ]
          }
        }
    }
