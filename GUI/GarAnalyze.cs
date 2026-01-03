namespace GARbro.GUI
{
    public class KeyAnalyze
    {
        public static string m_key_file_name = "C:\\Users\\kyoro\\source\\repos\\GARbro-Analyzer\\bin\\Debug\\KeyData\\key.txt"; //鍵データファイル名(フルパス)

        //ExHibit.GyuImage
        public static bool m_is_judged = false; //ピクセルの色判定フラグ
        public static uint m_gyu_key; //ImageGYU用の鍵(4バイト)

        //Kirikiri.CxEncription
        public static string AnalyzeFile = "startup.tjs"; //解析対象
        public static string OederText = "P0P2O5E6P0P0O3E2O3P1P2O3E5E0O4"; //期待されるコード文字列
        public static byte[] PrologOrder;
        public static byte[] OddBranchOrder;
        public static byte[] EvenBranchOrder;
    }
}