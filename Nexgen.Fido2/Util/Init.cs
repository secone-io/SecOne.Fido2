using Nexgen.Fido2.Interop;


namespace Nexgen.Fido2.Util
{
    internal static class Init
    {
        #region Variables

        private static bool _called;

        #endregion

        #region Public Methods

        public static void Call()
        {
            if (_called) {
                return;
            }

            _called = true;
            Native.fido_init((int)Fido2Settings.Flags);
        }

        #endregion
    }
}
